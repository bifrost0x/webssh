package client

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// noneServer accepts the "none" method for user, as tailssh does for an
// authorized node.
func noneServer(user string) *ssh.ServerConfig {
	return &ssh.ServerConfig{NoClientAuth: true, NoClientAuthCallback: func(c ssh.ConnMetadata) (*ssh.Permissions, error) {
		if c.User() != user {
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
}

var errNoMethod = errors.New("no method")

func noneOnly(AuthRequest) ssh.ClientAuthCallback {
	return func(*ssh.ClientAuthContext) (ssh.AuthMethod, error) { return nil, errNoMethod }
}

func TestVariantDialAndNoneAuth(t *testing.T) {
	s := startServer(t, noneServer("tsuser"))
	d, n := newDialer(trusting(s), nil)
	var dialed atomic.Int32
	tg := target(s, "tsuser", Auth{})
	tg.Variant = &Variant{Auth: noneOnly, Dial: func(ctx context.Context, h Hop) (net.Conn, error) {
		dialed.Add(1)
		if h.Host != s.host || h.Port != s.port || h.User == "" {
			t.Errorf("variant dial got %+v", h)
		}
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", joinHostPort(h.Host, h.Port))
	}}
	c, err := d.Dial(t.Context(), tg, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if dialed.Load() != 1 || len(n.dials) != 0 {
		t.Fatalf("variant dials %d, policy dials %v; the variant must replace the policy dial", dialed.Load(), n.dials)
	}
	tg.Hop.User = "other"
	_, err = d.Dial(t.Context(), tg, nil)
	if role, code := hopOf(t, err); role != RoleTarget || code != fault.SSHProtocol {
		t.Fatalf("refused none: %s %s", role, code)
	}
}

func TestVariantWithoutAuthStillNeedsCredentials(t *testing.T) {
	s := startServer(t, noneServer("u"))
	d, _ := newDialer(trusting(s), nil)
	tg := target(s, "u", Auth{})
	tg.Variant = &Variant{Ready: func(context.Context, *ssh.Client) error { return nil }}
	if _, err := d.Dial(t.Context(), tg, nil); fault.CodeOf(err) != fault.InvalidValue {
		t.Fatalf("missing credentials: %v", err)
	}
}

func TestVariantDialRefusesRoutes(t *testing.T) {
	s := startServer(t, noneServer("u"))
	d, _ := newDialer(trusting(s), nil)
	dial := func(context.Context, Hop) (net.Conn, error) { t.Fatal("dialed"); return nil, nil }
	tg := target(s, "u", Auth{})
	tg.Variant = &Variant{Auth: noneOnly, Dial: dial}
	tg.Jumps = []Hop{{Host: s.host, Port: s.port, User: "j", Auth: Auth{Password: "x"}}}
	if _, err := d.Dial(t.Context(), tg, nil); fault.CodeOf(err) != fault.InvalidRequest {
		t.Fatalf("jump with dial variant: %v", err)
	}
	tg.Jumps = nil
	tg.Proxy = &SOCKS{Host: "127.0.0.1", Port: 1080}
	if _, err := d.Dial(t.Context(), tg, nil); fault.CodeOf(err) != fault.InvalidRequest {
		t.Fatalf("proxy with dial variant: %v", err)
	}
}

func TestVariantAuthRunsOnEveryHop(t *testing.T) {
	calls := 0
	inner := startServer(t, passwordServer("inner", "pw2", &calls))
	jump := startServer(t, passwordServer("jump", "pw1", &calls))
	d, _ := newDialer(trusting(inner, jump), nil)
	var seen []AuthRequest
	tg := target(inner, "inner", Auth{})
	tg.Jumps = []Hop{{Host: jump.host, Port: jump.port, User: "jump", Auth: Auth{Password: "pw1"}}}
	tg.Variant = &Variant{Auth: func(r AuthRequest) ssh.ClientAuthCallback {
		seen = append(seen, r)
		used := false
		return func(*ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			if used {
				return nil, errNoMethod
			}
			used = true
			resume := r.Pause()
			resume()
			if r.Role == RoleTarget {
				return ssh.Password("pw2"), nil
			}
			return ssh.Password(r.Password), nil
		}
	}}
	c, err := d.Dial(t.Context(), tg, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(seen) != 2 || seen[0].Role != RoleJump || seen[1].Role != RoleTarget || seen[1].Password != "" {
		t.Fatalf("auth requests: %+v", seen)
	}
}

func TestVariantReadyFailureClosesTheConnection(t *testing.T) {
	s := startServer(t, noneServer("u"))
	d, _ := newDialer(trusting(s), nil)
	var got *ssh.Client
	tg := target(s, "u", Auth{})
	tg.Variant = &Variant{Auth: noneOnly, Ready: func(_ context.Context, c *ssh.Client) error {
		got = c
		return fault.New(fault.Unavailable, "not ready")
	}}
	_, err := d.Dial(t.Context(), tg, nil)
	if role, code := hopOf(t, err); role != RoleTarget || code != fault.Unavailable {
		t.Fatalf("ready failure: %s %s", role, code)
	}
	if got == nil {
		t.Fatal("ready not called")
	}
	if _, _, err := got.SendRequest("keepalive@openssh.com", true, nil); err == nil {
		t.Fatal("connection still open after a failed readiness check")
	}
}
