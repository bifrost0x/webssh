package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// openNet is a network policy that admits everything (client.Network).
type openNet struct{}

func (openNet) DialContext(ctx context.Context, _ netpolicy.Role, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (n openNet) DialRelay(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error) {
	return n.DialContext(ctx, role, network, addr)
}

func (openNet) JumpDestination(_ context.Context, host string, _ int, _ bool) (string, error) {
	return host, nil
}

func (openNet) SOCKSDestination(_ context.Context, host string, _ int, _ bool) (string, error) {
	return host, nil
}

// pinnedKeys trusts exactly the given host keys (client.HostKeys).
type pinnedKeys struct{ keys []ssh.PublicKey }

func (p pinnedKeys) Known(_ context.Context, _ int64, _ string, _ int, key ssh.PublicKey) (bool, error) {
	for _, k := range p.keys {
		if bytes.Equal(k.Marshal(), key.Marshal()) {
			return true, nil
		}
	}
	return false, nil
}

func (pinnedKeys) Record(context.Context, int64, string, int, ssh.PublicKey) error { return nil }

func (pinnedKeys) Preferred(_ context.Context, _ int64, _ string, _ int, allowed []string) ([]string, error) {
	return allowed, nil
}

type event struct {
	typ     string
	payload any
}

// events records what an attempt sends and passes it to a channel.
type events struct {
	mu   sync.Mutex
	all  []event
	ch   chan event
	gone bool
}

func newEvents() *events { return &events{ch: make(chan event, 256)} }

func (e *events) SendEvent(typ string, payload any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gone {
		return io.ErrClosedPipe
	}
	e.all = append(e.all, event{typ, payload})
	e.ch <- event{typ, payload}
	return nil
}

// browser plays the WebSSH page: it answers challenges with a script,
// acknowledges output and types into the gateway terminal.
type browser struct {
	owner  Owner
	ev     *events
	answer func(title string, prompts []Prompt) []string
	onText func(text string) string // keystrokes to send, "" for none
	noAck  bool
	// attempt is the attempt begin started for this browser.
	attempt *Attempt

	mu      sync.Mutex
	output  bytes.Buffer
	prompts [][]Prompt
	shown   []protocol.PromptInteractive
}

func newBrowser() *browser {
	return &browser{owner: Owner{Peer: 3, UserID: 7}, ev: newEvents()}
}

func (b *browser) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.output.String()
}

func (b *browser) asked() [][]Prompt {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]Prompt(nil), b.prompts...)
}

func (b *browser) challenges() []protocol.PromptInteractive {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]protocol.PromptInteractive(nil), b.shown...)
}

// run drives one attempt until ctx ends.
func (b *browser) run(ctx context.Context, a *Attempt) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-b.ev.ch:
			switch p := ev.payload.(type) {
			case protocol.PromptInteractive:
				prompts := make([]Prompt, len(p.Prompts))
				for i, q := range p.Prompts {
					prompts[i] = Prompt{Label: q.Label, Echo: q.Echo}
				}
				b.mu.Lock()
				b.prompts = append(b.prompts, prompts)
				b.shown = append(b.shown, p)
				b.mu.Unlock()
				if b.answer != nil {
					if ans := b.answer(p.Title, prompts); ans != nil {
						a.Answer(b.owner, p.PromptID, ans)
					}
				}
			case protocol.GatewayOutput:
				b.mu.Lock()
				b.output.WriteString(p.Data)
				b.mu.Unlock()
				if !b.noAck {
					a.Ack(b.owner, p.Sequence)
				}
				if b.onText != nil {
					if keys := b.onText(b.text()); keys != "" {
						a.Input(b.owner, keys)
					}
				}
			}
		}
	}
}

// begin starts an attempt for the browser in a fresh registry.
func begin(t *testing.T, ctx context.Context, b *browser, gateway bool) (*Attempt, context.Context) {
	t.Helper()
	r := &Registry{}
	a, actx, end, err := r.Begin(ctx, b.owner, "req-1", b.ev, gateway)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(end)
	b.attempt = a
	bctx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	go b.run(bctx, a)
	return a, actx
}

// dialVia connects to the stand-in with the shared dialer and the
// attempt's variant: terminal runs the readiness probe of a gateway
// terminal, after replaces it with another check on the connection.
func dialVia(ctx context.Context, t *testing.T, g *standIn, user string, auth client.Auth, signer ssh.Signer,
	a *Attempt, terminal bool, after func(context.Context, *ssh.Client) error) (*client.Conn, error) {
	t.Helper()
	keys := keySource{}
	if signer != nil {
		auth.KeyID = "k1"
		keys["k1"] = signer
	}
	v := a.Variant(terminal)
	if after != nil {
		v.Ready = after
	}
	d := &client.Dialer{Net: openNet{}, HostKeys: pinnedKeys{[]ssh.PublicKey{g.hostKey}}, Keys: keys, Keepalive: -1}
	c, err := d.Dial(ctx, client.Target{Owner: 7, Hop: client.Hop{Host: "127.0.0.1", Port: g.port, User: user, Auth: auth},
		Variant: v}, nil)
	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

type keySource map[string]ssh.Signer

func (k keySource) Signer(_ context.Context, _ int64, id string) (ssh.Signer, error) {
	s, ok := k[id]
	if !ok {
		return nil, fmt.Errorf("no key %s", id)
	}
	return s, nil
}

// sftpHandshake opens the SFTP subsystem and returns the server's version
// (SSH_FXP_INIT / SSH_FXP_VERSION, draft-ietf-secsh-filexfer-02).
func sftpHandshake(ctx context.Context, c *ssh.Client) (byte, error) {
	s, err := c.NewSession()
	if err != nil {
		return 0, err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	defer func() { _ = s.Close() }()
	in, err := s.StdinPipe()
	if err != nil {
		return 0, err
	}
	out, err := s.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := s.RequestSubsystem("sftp"); err != nil {
		return 0, err
	}
	if _, err := in.Write([]byte{0, 0, 0, 5, 1, 0, 0, 0, 3}); err != nil {
		return 0, err
	}
	var hdr [9]byte
	if _, err := io.ReadFull(out, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[4] != 2 {
		return 0, fmt.Errorf("sftp: unexpected packet type %d", hdr[4])
	}
	return byte(binary.BigEndian.Uint32(hdr[5:])), nil
}
