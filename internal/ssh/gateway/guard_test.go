package gateway

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// countingGuard counts its checks and returns err.
type countingGuard struct {
	calls atomic.Int32
	err   error
}

func (g *countingGuard) Check(context.Context) error {
	g.calls.Add(1)
	return g.err
}

func refusing() *countingGuard {
	return &countingGuard{err: fault.New(fault.CredentialTargetChanged, "")}
}

// A saved password whose guard refuses never reaches the gateway, for an
// ordinary username, a selector and the password fallback after a
// promptless keyboard-interactive failure. A guard that accepts lets the
// password through once.
func TestGatewaySavedPasswordIsGuarded(t *testing.T) {
	for _, tc := range []struct{ name, methods, user string }{
		{"ordinary user", "password", "alice"},
		{"selector", "password", "alice:prod"},
		{"promptless fallback", "ki-broken+password", "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			g, _ := newStandIn(t, tc.methods)
			a, actx := begin(t, ctx, newBrowser(), true)
			guard := refusing()
			_, err := dialVia(actx, t, g, tc.user, client.Auth{Password: g.password, Guard: guard}, nil, a, false,
				func(context.Context, *ssh.Client) error { return nil })
			if slices.Contains(g.used(), "password") {
				t.Fatalf("saved password sent despite a refusing guard (used %v)", g.used())
			}
			if fault.CodeOf(err) != fault.CredentialTargetChanged || guard.calls.Load() != 1 {
				t.Fatalf("err %v (%s), guard calls %d", err, fault.CodeOf(err), guard.calls.Load())
			}

			g2, _ := newStandIn(t, tc.methods)
			a2, actx2 := begin(t, ctx, newBrowser(), true)
			ok := &countingGuard{}
			if _, err := dialVia(actx2, t, g2, tc.user, client.Auth{Password: g2.password, Guard: ok}, nil, a2, false,
				func(context.Context, *ssh.Client) error { return nil }); err != nil {
				t.Fatalf("accepting guard: %v", err)
			}
			if ok.calls.Load() != 1 {
				t.Fatalf("guard calls %d, want 1", ok.calls.Load())
			}
		})
	}
}

// A jump host in front of the gateway authenticates with the gateway
// strategy too: its saved password is guarded the same way, and the
// gateway behind it is never reached.
func TestGatewayJumpSavedPasswordIsGuarded(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	jump, _ := newStandIn(t, "password")
	gw, _ := newStandIn(t, "password")
	a, actx := begin(t, ctx, newBrowser(), true)
	guard := refusing()
	d := &client.Dialer{Net: openNet{}, HostKeys: pinnedKeys{[]ssh.PublicKey{jump.hostKey, gw.hostKey}}, Keys: keySource{}, Keepalive: -1}
	_, err := d.Dial(actx, client.Target{Owner: 7,
		Jumps:   []client.Hop{{Host: "127.0.0.1", Port: jump.port, User: "bastion", Auth: client.Auth{Password: jump.password, Guard: guard}}},
		Hop:     client.Hop{Host: "127.0.0.1", Port: gw.port, User: "alice:prod", Auth: client.Auth{Password: gw.password}},
		Variant: a.Variant(false)}, nil)
	if fault.CodeOf(err) != fault.CredentialTargetChanged || guard.calls.Load() != 1 {
		t.Fatalf("err %v (%s), guard calls %d", err, fault.CodeOf(err), guard.calls.Load())
	}
	if len(jump.used()) != 0 || len(gw.used()) != 0 {
		t.Fatalf("jump saw %v, gateway saw %v", jump.used(), gw.used())
	}
}
