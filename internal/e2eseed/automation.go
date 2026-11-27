package e2eseed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// AutomationPeer is the disposable loopback SSH server of the hook
// automation_ssh_peer (tests/e2e/automation_fixture.py): user "fixture"
// with the seeded key. A command is the exec request, as the Python
// fixture reads it; it prints "fixture command completed", "fail" exits 2,
// "wait" waits until the channel closes (at most 20 s).
type AutomationPeer struct {
	ln       net.Listener
	hostKey  ssh.Signer
	client   ed25519.PrivateKey
	accounts []string
	wg       sync.WaitGroup
}

// AutomationProfile is the saved host each account of the hook gets.
const (
	automationProfileID   = "automation-fixture"
	automationProfileName = "Automation fixture"
	automationGroup       = "Automation lab"
	automationUser        = "fixture"
)

// StartAutomationPeer starts the peer of the hook, or returns nil when the
// seed does not enable it.
func (s *Seed) StartAutomationPeer() (*AutomationPeer, error) {
	var accounts []string
	for _, h := range s.TestHooks {
		if h.Name == HookAutomationSSHPeer {
			accounts = h.Accounts
		}
	}
	if accounts == nil {
		return nil, nil
	}
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hostKey, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		return nil, err
	}
	_, client, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("automation peer: %w", err)
	}
	p := &AutomationPeer{ln: ln, hostKey: hostKey, client: client, accounts: accounts}
	p.wg.Go(p.serve)
	return p, nil
}

// Addr is the host:port the peer listens on.
func (p *AutomationPeer) Addr() string { return p.ln.Addr().String() }

// Port is the port the peer listens on.
func (p *AutomationPeer) Port() int {
	_, port, _ := net.SplitHostPort(p.Addr())
	n, _ := strconv.Atoi(port)
	return n
}

// HostKey is the peer's public host key, trusted for the seeded accounts.
func (p *AutomationPeer) HostKey() ssh.PublicKey { return p.hostKey.PublicKey() }

// Close stops the peer and its connections.
func (p *AutomationPeer) Close() error {
	err := p.ln.Close()
	p.wg.Wait()
	return err
}

func (p *AutomationPeer) config() *ssh.ServerConfig {
	allowed, _ := ssh.NewPublicKey(p.client.Public())
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() == automationUser && string(key.Marshal()) == string(allowed.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("e2e automation peer: key refused")
	}}
	cfg.AddHostKey(p.hostKey)
	return cfg
}

func (p *AutomationPeer) serve() {
	cfg := p.config()
	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		conns.Go(func() { p.conn(c, cfg) })
	}
}

func (p *AutomationPeer) conn(c net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Minute))
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "session only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go session(ch, creqs)
	}
}

func session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	closed := make(chan struct{})
	execed := make(chan string, 1)
	go func() {
		defer close(closed)
		for r := range reqs {
			var req struct{ Command string }
			ok := r.Type == "exec" && ssh.Unmarshal(r.Payload, &req) == nil
			if r.WantReply {
				_ = r.Reply(ok, nil)
			}
			if ok {
				select {
				case execed <- req.Command:
				default:
				}
			}
		}
	}()
	var command string
	select {
	case command = <-execed:
	case <-closed:
		_ = ch.Close()
		return
	}
	status := uint32(0)
	switch command {
	case "wait":
		select {
		case <-closed:
			return
		case <-time.After(20 * time.Second):
		}
	case "fail":
		status = 2
	}
	_, _ = ch.Write([]byte("fixture command completed\n"))
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	_ = ch.CloseWrite()
	_ = ch.Close()
}

// seedAccount stores the peer's client key for the account, trusts the
// peer's host key and returns the saved host in the group "Automation
// lab", as the Python fixture seeds it.
func (p *AutomationPeer) seedAccount(ctx context.Context, st Stores, owner int64) (ProfileRecord, error) {
	keyID, err := st.Keys.AddKey(ctx, owner, "Automation fixture key", p.client)
	if err != nil {
		return ProfileRecord{}, err
	}
	if err := st.HostKeys.Record(ctx, owner, "127.0.0.1", p.Port(), p.HostKey()); err != nil {
		return ProfileRecord{}, err
	}
	return ProfileRecord{ID: automationProfileID, Name: automationProfileName, Host: "127.0.0.1", Port: p.Port(),
		Username: automationUser, Auth: "key", KeyID: keyID, Group: automationGroup, StartupMode: "none"}, nil
}
