package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
)

// The connection keeps the address it was pinned to and what each relay
// was asked to reach, so an open connection can be checked against a
// network rule that changed later.
func TestRouteOfDirectAndJumpConnections(t *testing.T) {
	calls := 0
	inner := startServer(t, passwordServer("in", "pw2", &calls))
	middle := startServer(t, passwordServer("mid", "pw1", &calls))
	outer := startServer(t, passwordServer("out", "pw0", &calls))
	d, _ := newDialer(trusting(), nil)
	ix := &prompts{accept: true}

	direct, err := d.Dial(t.Context(), target(inner, "in", Auth{Password: "pw2"}), ix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = direct.Close() })
	r, ok := direct.Route()
	if !ok || r.Peer != netip.MustParseAddr(inner.host) || len(r.Onward) != 0 {
		t.Fatalf("direct route %+v %v", r, ok)
	}

	chain, err := d.Dial(t.Context(), Target{Owner: 1,
		Jumps: []Hop{
			{Host: outer.host, Port: outer.port, User: "out", Auth: Auth{Password: "pw0"}},
			{Host: middle.host, Port: middle.port, User: "mid", Auth: Auth{Password: "pw1"}},
		},
		Hop: Hop{Host: inner.host, Port: inner.port, User: "in", Auth: Auth{Password: "pw2"}},
	}, ix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = chain.Close() })
	r, ok = chain.Route()
	if !ok || r.Peer != netip.MustParseAddr(outer.host) || !slices.Equal(r.Onward, []string{middle.host, inner.host}) {
		t.Fatalf("jump route %+v %v", r, ok)
	}
	// The caller cannot change the connection's record.
	r.Onward[0] = "changed"
	if again, _ := chain.Route(); again.Onward[0] != middle.host {
		t.Fatal("Route shares its slice with the caller")
	}
}

func TestRouteThroughSOCKS(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	proxy := startSOCKS(t)
	d, _ := newDialer(trusting(), nil)
	tg := target(s, "u", Auth{Password: "pw"})
	tg.Proxy = &SOCKS{Host: "127.0.0.1", Port: proxy}
	c, err := d.Dial(t.Context(), tg, &prompts{accept: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	r, ok := c.Route()
	if !ok || r.Peer != netip.MustParseAddr("127.0.0.1") || !slices.Equal(r.Onward, []string{s.host}) {
		t.Fatalf("socks route %+v %v", r, ok)
	}
}

// A connection the variant dialled itself (Tailscale SSH) has no route of
// the network policy: it is exempt from the tailnet rule.
func TestRouteOfVariantDialIsUnknown(t *testing.T) {
	s := startServer(t, noneServer("tsuser"))
	d, _ := newDialer(trusting(s), nil)
	tg := target(s, "tsuser", Auth{})
	tg.Variant = &Variant{Auth: noneOnly, Dial: func(ctx context.Context, h Hop) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", joinHostPort(h.Host, h.Port))
	}}
	c, err := d.Dial(t.Context(), tg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if r, ok := c.Route(); ok {
		t.Fatalf("variant route %+v", r)
	}
}

// startSOCKS runs a SOCKS5 proxy without authentication that accepts IPv4
// destinations and relays them; it returns its port.
func startSOCKS(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go relaySOCKS(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func relaySOCKS(c net.Conn) {
	defer func() { _ = c.Close() }()
	head := make([]byte, 3)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 10)
	if _, err := io.ReadFull(c, req); err != nil || req[3] != 1 {
		return
	}
	dest := net.JoinHostPort(netip.AddrFrom4([4]byte(req[4:8])).String(), strconv.Itoa(int(binary.BigEndian.Uint16(req[8:]))))
	up, err := net.Dial("tcp", dest)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(up, c)
		_ = up.Close()
	}()
	_, _ = io.Copy(c, up)
}
