package tailscale

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

func clientHop(host string, port int, user string) client.Hop {
	return client.Hop{Host: host, Port: port, User: user}
}

// tailsshStandIn accepts "none" for one user, as tailssh does for an
// authorized node, and counts the methods it was offered.
func tailsshStandIn(t *testing.T, user string) (netip.AddrPort, ssh.PublicKey, *[]string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	var mu sync.Mutex
	var offered []string
	cfg := &ssh.ServerConfig{
		NoClientAuth: true,
		NoClientAuthCallback: func(c ssh.ConnMetadata) (*ssh.Permissions, error) {
			mu.Lock()
			offered = append(offered, "none")
			mu.Unlock()
			if c.User() != user {
				return nil, errors.New("denied")
			}
			return nil, nil
		},
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			mu.Lock()
			offered = append(offered, "password")
			mu.Unlock()
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
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
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					_ = nc.Reject(ssh.Prohibited, "no channels")
				}
			})
		}
	})
	return netip.MustParseAddrPort(ln.Addr().String()), signer.PublicKey(), &offered
}

type pinned struct{ key ssh.PublicKey }

func (p pinned) Known(_ context.Context, _ int64, _ string, _ int, key ssh.PublicKey) (bool, error) {
	if !bytes.Equal(p.key.Marshal(), key.Marshal()) {
		return false, fault.New(fault.HostKeyChanged, "")
	}
	return true, nil
}
func (pinned) Record(context.Context, int64, string, int, ssh.PublicKey) error { return nil }
func (pinned) Preferred(_ context.Context, _ int64, _ string, _ int, a []string) ([]string, error) {
	return a, nil
}

// refusingNet fails the test if the ordinary policy dial is used.
type refusingNet struct{ t *testing.T }

func (n refusingNet) DialContext(context.Context, netpolicy.Role, string, string) (net.Conn, error) {
	n.t.Error("the policy dial was used for Tailscale SSH")
	return nil, errors.New("refused")
}
func (n refusingNet) DialRelay(ctx context.Context, r netpolicy.Role, nw, a string) (net.Conn, error) {
	return n.DialContext(ctx, r, nw, a)
}
func (refusingNet) JumpDestination(context.Context, string, int, bool) (string, error) {
	return "", errors.New("refused")
}
func (refusingNet) SOCKSDestination(context.Context, string, int, bool) (string, error) {
	return "", errors.New("refused")
}

func TestVariantConnectsThePinnedAddressWithNone(t *testing.T) {
	addr, hostKey, offered := tailsshStandIn(t, "tsuser")
	var dialed []string
	dialInterface = func(ctx context.Context, iface string, to netip.AddrPort) (net.Conn, error) {
		dialed = append(dialed, iface+" "+to.String())
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", to.String())
	}
	t.Cleanup(func() { dialInterface = netpolicy.DialInterface })
	p := New(Config{Enabled: true, Interface: "tailscale0", AllowedTargets: []Target{{"node.ts.lan", int(addr.Port())}}},
		func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{addr.Addr()}, nil },
		func(context.Context, netip.Addr) (netpolicy.Route, error) {
			return netpolicy.Route{Interface: "tailscale0", Table: 52}, nil
		})
	admin := User{ID: 9, Username: "root-admin", IsAdmin: true}
	a, err := p.Authorize(t.Context(), admin, "node.ts.lan", int(addr.Port()), "tsuser")
	if err != nil {
		t.Fatal(err)
	}
	d := &client.Dialer{Net: refusingNet{t}, HostKeys: pinned{hostKey}, Keepalive: -1}
	target := client.Target{Owner: 9, Hop: client.Hop{Host: "node.ts.lan", Port: int(addr.Port()), User: "tsuser"}, Variant: a.Variant()}
	c, err := d.Dial(t.Context(), target, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(dialed) != 1 || dialed[0] != "tailscale0 "+addr.String() {
		t.Fatalf("dials %v", dialed)
	}

	// A hop that is not the authorized one is refused before any packet.
	other := target
	other.Hop.User = "root"
	if _, err := d.Dial(t.Context(), other, nil); !errors.Is(err, ErrAuthorizationGone) {
		t.Fatalf("other remote user: %v", err)
	}
	// The node is not accepted: no other method is offered.
	b, err := p.Authorize(t.Context(), admin, "node.ts.lan", int(addr.Port()), "nobody")
	if err != nil {
		t.Fatal(err)
	}
	nobody := target
	nobody.Hop.User, nobody.Variant = "nobody", b.Variant()
	*offered = nil
	if _, err := d.Dial(t.Context(), nobody, nil); fault.CodeOf(err) != fault.AuthFailed {
		t.Fatalf("refused node: %v", err)
	}
	for _, m := range *offered {
		if m != "none" {
			t.Fatalf("offered %v after none was refused", *offered)
		}
	}
	// A changed host key is refused as for every host.
	d.HostKeys = pinned{mustKey(t)}
	if _, err := d.Dial(t.Context(), target, nil); fault.CodeOf(err) != fault.HostKeyChanged {
		t.Fatalf("changed host key: %v", err)
	}
}

func mustKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
