package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

// testServer is an in-process SSH server. It forwards direct-tcpip
// channels, so servers can be chained as jump hosts, and runs an echo
// shell that records window changes.
type testServer struct {
	host    string
	port    int
	hostKey ssh.PublicKey

	mu      sync.Mutex
	resizes [][2]uint32
	forward []string
	// silent stops answering global requests, like a peer that died.
	silent chan struct{}
}

func startServer(t *testing.T, cfg *ssh.ServerConfig) *testServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{host: "127.0.0.1", port: l.Addr().(*net.TCPAddr).Port, hostKey: signer.PublicKey(), silent: make(chan struct{})}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { s.serve(conn, cfg) })
		}
	})
	return s
}

func (s *testServer) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go func() {
		for req := range reqs {
			select {
			case <-s.silent:
				// Never answer; drain so the connection stays readable.
				continue
			default:
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for nc := range chans {
		switch nc.ChannelType() {
		case "direct-tcpip":
			wg.Go(func() { s.forwardChannel(nc) })
		case "session":
			wg.Go(func() { s.session(nc) })
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "")
		}
	}
}

func (s *testServer) forwardChannel(nc ssh.NewChannel) {
	extra := nc.ExtraData()
	if len(extra) < 4 {
		_ = nc.Reject(ssh.ConnectionFailed, "")
		return
	}
	n := binary.BigEndian.Uint32(extra)
	if int(n)+8 > len(extra) {
		_ = nc.Reject(ssh.ConnectionFailed, "")
		return
	}
	host := string(extra[4 : 4+n])
	port := binary.BigEndian.Uint32(extra[4+n:])
	s.mu.Lock()
	s.forward = append(s.forward, host)
	s.mu.Unlock()
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ch, target); _ = ch.CloseWrite(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(target, ch); done <- struct{}{} }()
	<-done
	_ = ch.Close()
	_ = target.Close()
	<-done
}

func (s *testServer) session(nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "window-change":
			if len(req.Payload) >= 8 {
				s.mu.Lock()
				s.resizes = append(s.resizes, [2]uint32{binary.BigEndian.Uint32(req.Payload), binary.BigEndian.Uint32(req.Payload[4:])})
				s.mu.Unlock()
			}
		case "shell":
			_ = req.Reply(true, nil)
			go func() {
				// Echo until the client sends "exit\n".
				buf := make([]byte, 256)
				var seen []byte
				for {
					n, err := ch.Read(buf)
					if n > 0 {
						_, _ = ch.Write(buf[:n])
						seen = append(seen, buf[:n]...)
					}
					if err != nil || bytes.Contains(seen, []byte("exit\n")) {
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						_ = ch.Close()
						return
					}
				}
			}()
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// directNet is a Network without a policy for unit tests: it dials what
// it is given and passes names to relays unchanged.
type directNet struct {
	mu    sync.Mutex
	dials []string
	err   error
}

func (n *directNet) DialContext(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dials = append(n.dials, string(role)+" "+addr)
	n.mu.Unlock()
	if n.err != nil {
		return nil, n.err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (n *directNet) DialRelay(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error) {
	return n.DialContext(ctx, role+"-relay", network, addr)
}

func (n *directNet) JumpDestination(_ context.Context, host string, _ int, _ bool) (string, error) {
	return host, nil
}

func (n *directNet) SOCKSDestination(_ context.Context, host string, _ int, _ bool) (string, error) {
	return host, nil
}

// memHostKeys is an in-memory trust store with the semantics of
// internal/ssh/hostkey.
type memHostKeys struct {
	mu        sync.Mutex
	keys      map[string]ssh.PublicKey
	recorded  int
	recordErr error
	knownErr  error
}

func trusting(keys ...*testServer) *memHostKeys {
	m := &memHostKeys{keys: map[string]ssh.PublicKey{}}
	for _, s := range keys {
		m.keys[joinHostPort(s.host, s.port)] = s.hostKey
	}
	return m
}

func (m *memHostKeys) Known(ctx context.Context, _ int64, host string, port int, key ssh.PublicKey) (bool, error) {
	if err := ctx.Err(); err != nil {
		// Like the database-backed store.
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.knownErr != nil {
		return false, m.knownErr
	}
	k, ok := m.keys[joinHostPort(host, port)]
	if !ok {
		return false, nil
	}
	if !bytes.Equal(k.Marshal(), key.Marshal()) {
		return false, fault.New(fault.HostKeyChanged, "")
	}
	return true, nil
}

func (m *memHostKeys) Record(_ context.Context, _ int64, host string, port int, key ssh.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recorded++
	if m.recordErr != nil {
		return m.recordErr
	}
	m.keys[joinHostPort(host, port)] = key
	return nil
}

func (m *memHostKeys) Preferred(_ context.Context, _ int64, _ string, _ int, allowed []string) ([]string, error) {
	return allowed, nil
}

// prompts is a scripted Interaction.
type prompts struct {
	mu       sync.Mutex
	hostKeys []HostKeyPrompt
	banners  []BannerPrompt
	accept   bool
	banner   bool
	err      error
	block    bool // wait for the context instead of answering
}

func (p *prompts) HostKey(ctx context.Context, q HostKeyPrompt) (bool, error) {
	p.mu.Lock()
	p.hostKeys = append(p.hostKeys, q)
	p.mu.Unlock()
	if p.block {
		<-ctx.Done()
		return false, ctx.Err()
	}
	return p.accept, p.err
}

func (p *prompts) Banner(_ context.Context, q BannerPrompt) (bool, error) {
	p.mu.Lock()
	p.banners = append(p.banners, q)
	p.mu.Unlock()
	return p.banner, p.err
}

type keyMap map[string]ssh.Signer

func (k keyMap) Signer(_ context.Context, _ int64, id string) (ssh.Signer, error) {
	s, ok := k[id]
	if !ok {
		return nil, fault.New(fault.NotFound, "")
	}
	return s, nil
}

func target(s *testServer, user string, auth Auth) Target {
	return Target{Owner: 1, Hop: Hop{Host: s.host, Port: s.port, User: user, Auth: auth}}
}

func newDialer(hk HostKeys, keys KeySource) (*Dialer, *directNet) {
	n := &directNet{}
	return &Dialer{Net: n, HostKeys: hk, Keys: keys, Keepalive: -1}, n
}

// hopOf returns the role and code of a dialer error.
func hopOf(t *testing.T, err error) (Role, fault.Code) {
	t.Helper()
	he, ok := errors.AsType[*HopError](err)
	if !ok {
		t.Fatalf("no hop in %v", err)
	}
	return he.Role, fault.CodeOf(err)
}

func passwordServer(user, password string, calls *int) *ssh.ServerConfig {
	var mu sync.Mutex
	return &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		mu.Lock()
		*calls++
		mu.Unlock()
		if c.User() == user && string(pw) == password {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
}
