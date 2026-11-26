package terminal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// startChannelHolder starts an SSH server that accepts every login and
// answers keepalives but never confirms or rejects a channel, like the
// server of R2 M-1. channels receives one value per held channel.
func startChannelHolder(t *testing.T) (addr *net.TCPAddr, key ssh.PublicKey, channels <-chan struct{}) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{}, 64)
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer func() { _ = sc.Close() }()
				go func() {
					for req := range reqs {
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
					}
				}()
				for range chans {
					held <- struct{}{}
				}
			})
		}
	})
	return l.Addr().(*net.TCPAddr), signer.PublicKey(), held
}

// newHolderManager wires the terminal with the real dialer, network
// policy and host-key store; the holder's key is trusted beforehand.
func newHolderManager(t *testing.T, addr *net.TCPAddr, key ssh.PublicKey, budget time.Duration) *Manager {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	policy, err := netpolicy.New(netpolicy.Config{Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	keys := hostkey.New(storetest.Open(t, hostkey.Schema()), log)
	if err := keys.Record(t.Context(), 1, addr.IP.String(), addr.Port, key); err != nil {
		t.Fatal(err)
	}
	dialer := &client.Dialer{Net: policy, HostKeys: keys, HandshakeTimeout: budget}
	profiles := fakeProfiles{"evil": {Owner: 1, Hop: client.Hop{Host: addr.IP.String(), Port: addr.Port, User: "u", Auth: client.Auth{Password: "pw"}}}}
	m, err := New(Config{SessionsGlobal: 2, SessionsPerUser: 2}, Deps{Shells: dialer, Profiles: profiles, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	return m
}

func openHolder(t *testing.T, m *Manager, peer protocol.Peer, id string) <-chan *protocol.Error {
	done := make(chan *protocol.Error, 1)
	go func() {
		done <- call(t, m, peer, protocol.TypeTerminalOpen, protocol.TerminalOpen{Ch: 1, RequestID: id, Rows: 24, Cols: 80,
			Target: protocol.OpenTarget{ProfileID: "evil", AuthType: "password"}}, nil)
	}()
	return done
}

func waitOpen(t *testing.T, done <-chan *protocol.Error) *protocol.Error {
	t.Helper()
	select {
	case werr := <-done:
		return werr
	case <-time.After(10 * time.Second):
		t.Fatal("terminal.open still waiting for the channel")
		return nil
	}
}

// A server that never confirms the session channel must not keep the
// quota: terminal.open ends with timeout after the handshake budget and
// every slot is free again (R2 M-1).
func TestStalledChannelFreesQuota(t *testing.T) {
	addr, key, _ := startChannelHolder(t)
	m := newHolderManager(t, addr, key, 300*time.Millisecond)
	for round := range 3 {
		var waits []<-chan *protocol.Error
		for i := range 2 {
			waits = append(waits, openHolder(t, m, user(t, 1), string(rune('a'+round*2+i))))
		}
		for _, w := range waits {
			if werr := waitOpen(t, w); werr == nil || werr.Code != fault.Timeout {
				t.Fatalf("round %d: %+v, want timeout", round, werr)
			}
		}
		if st := m.Stats(); st.Reserved != 0 || st.Sessions != 0 {
			t.Fatalf("round %d: quota still held: %+v", round, st)
		}
	}
}

// terminal.cancel ends an attempt that waits for the channel at once.
func TestStalledChannelCancel(t *testing.T) {
	addr, key, held := startChannelHolder(t)
	m := newHolderManager(t, addr, key, time.Minute)
	peer := user(t, 1)
	done := openHolder(t, m, peer, "c")
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("no channel reached the server")
	}
	if werr := call(t, m, peer, protocol.TypeTerminalCancel, protocol.TerminalCancel{RequestID: "c"}, nil); werr != nil {
		t.Fatalf("cancel: %+v", werr)
	}
	if werr := waitOpen(t, done); werr == nil || werr.Code != fault.Cancelled {
		t.Fatalf("%+v, want cancelled", werr)
	}
	if st := m.Stats(); st.Reserved != 0 {
		t.Fatalf("quota still held: %+v", st)
	}
}
