//go:build linux

package netpolicy

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// These tests talk to the real kernel. They always run on the host for
// loopback; the namespace cases run only where testdata/netns-test.sh sets
// WEBSSH_NETNS ("lab" inside lab-ts-node, "crafted" in an own namespace).

func TestLookupRouteLoopback(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.8.9.10"} {
		r, err := LookupRoute(t.Context(), netip.MustParseAddr(s))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if r.Interface != "lo" || !r.Local {
			t.Fatalf("%s: got %+v, want local route via lo", s, r)
		}
	}
}

func TestLookupRouteHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := LookupRoute(ctx, netip.MustParseAddr("127.0.0.1")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
	ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := LookupRoute(ctx, netip.MustParseAddr("127.0.0.1")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired context: %v", err)
	}
}

func TestLookupRouteParallel(t *testing.T) {
	// Each lookup owns its socket; sequence numbers must not collide.
	errs := make(chan error, 32)
	for range 32 {
		go func() {
			r, err := LookupRoute(t.Context(), netip.MustParseAddr("127.0.0.1"))
			if err == nil && r.Interface != "lo" {
				err = errors.New("wrong interface " + r.Interface)
			}
			errs <- err
		}()
	}
	for range 32 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

type routeCase struct {
	addr      string
	iface     string // "" = lookup must fail
	local     bool
	table     uint32
	restrict  bool // Tailnet{Interface: "tailscale0", FeatureEnabled: true}
	relayDeny bool
}

func runRouteCases(t *testing.T, cases []routeCase) {
	t.Helper()
	rule := Tailnet{Interface: "tailscale0", FeatureEnabled: true}
	for _, c := range cases {
		addr := netip.MustParseAddr(c.addr)
		r, err := LookupRoute(t.Context(), addr)
		switch {
		case c.iface == "" && err == nil:
			t.Errorf("%s: expected lookup failure, got %+v", c.addr, r)
		case c.iface != "" && err != nil:
			t.Errorf("%s: %v", c.addr, err)
		case c.iface != "" && (r.Interface != c.iface || r.Local != c.local || (c.table != 0 && r.Table != c.table)):
			t.Errorf("%s: got %+v, want %s local=%v table=%d", c.addr, r, c.iface, c.local, c.table)
		}
		if got := rule.targetRestricted(t.Context(), addr); got != c.restrict {
			t.Errorf("%s: TargetRestricted = %v, want %v", c.addr, got, c.restrict)
		}
		if got := rule.relayRestricted(t.Context(), addr); got != c.relayDeny {
			t.Errorf("%s: RelayRestricted = %v, want %v", c.addr, got, c.relayDeny)
		}
		t.Logf("%-28s -> %+v err=%v restricted=%v", c.addr, r, err, rule.targetRestricted(t.Context(), addr))
	}
}

// Lab stand-in: tailscale0 100.100.100.2/24, 100.64.0.0/10 only in table 52
// behind rule 5270, default route via eth0, no IPv6 route.
func TestLabTailscaleNamespace(t *testing.T) {
	if os.Getenv("WEBSSH_NETNS") != "lab" {
		t.Skip("run with testdata/netns-test.sh lab")
	}
	runRouteCases(t, []routeCase{
		{addr: "100.100.100.10", iface: "tailscale0", table: 52, restrict: true},
		{addr: "100.64.0.1", iface: "tailscale0", table: 52, restrict: true},
		{addr: "::ffff:100.100.100.10", iface: "tailscale0", table: 52, restrict: true},
		{addr: "100.100.100.2", iface: "lo", local: true, table: 255, restrict: true, relayDeny: true},
		{addr: "8.8.8.8", iface: "eth0", table: 254},
		{addr: "fd7a:115c:a1e0::1", iface: "", restrict: true, relayDeny: true}, // ENETUNREACH: fail closed
		{addr: "fd7a:115c:a1e0:b1a::a00:1", iface: "", relayDeny: true},         // 4via6 is no node; relay unknown
	})
	// D-28 with the real kernel and the real interface probe: the
	// Tailscale SSH feature is off, the host is a node, the rule applies.
	p, err := New(Config{Tailnet: Tailnet{Interface: "tailscale0"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Admit(t.Context(), RoleSSH, "100.100.100.10", 22); !errors.Is(err, ErrTailnetRestricted) {
		t.Errorf("tailnet node with the feature off: %v", err)
	}
	if _, err := p.Admit(t.Context(), RoleSSH, "8.8.8.8", 22); err != nil {
		t.Errorf("public address: %v", err)
	}
	// D-28 under D-01 with the real kernel: an upgraded installation keeps
	// ordinary SSH to the node while Tailscale SSH is off, and the gap is
	// reported; with the switch on the rule applies again.
	legacy, err := New(Config{Tailnet: Tailnet{Interface: "tailscale0", FollowsSwitch: func() bool { return true }}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Admit(t.Context(), RoleSSH, "100.100.100.10", 22); err != nil || !legacy.TailnetLegacyGap() {
		t.Errorf("upgraded installation with Tailscale SSH off: %v, gap %v", err, legacy.TailnetLegacyGap())
	}
	legacyOn, err := New(Config{Tailnet: Tailnet{Interface: "tailscale0", FeatureEnabled: true, FollowsSwitch: func() bool { return true }}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyOn.Admit(t.Context(), RoleSSH, "100.100.100.10", 22); !errors.Is(err, ErrTailnetRestricted) {
		t.Errorf("upgraded installation with Tailscale SSH on: %v", err)
	}
	noResolve := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no resolver") }
	if !(Tailnet{Interface: "tailscale0"}).remoteNameRestricted(t.Context(), "ts-target-alias.ts.net", noResolve) {
		t.Error("MagicDNS name must be refused")
	}
}

// Own namespace (testdata/netns-crafted.sh): tailscale0 and lan0 as dummy
// interfaces, table 52 with node routes, CGNAT 100.80.0.0/16 on lan0 in the
// main table, blackhole and prohibit routes, IPv6 node route.
func TestCraftedNamespace(t *testing.T) {
	if os.Getenv("WEBSSH_NETNS") != "crafted" {
		t.Skip("run with testdata/netns-test.sh crafted")
	}
	runRouteCases(t, []routeCase{
		{addr: "100.100.1.1", iface: "tailscale0", table: 52, restrict: true},
		{addr: "fd7a:115c:a1e0::9", iface: "tailscale0", table: 52, restrict: true},
		{addr: "fd7a:115c:a1e0:b1a::a00:1", iface: "tailscale0", table: 52}, // 4via6: no node address
		{addr: "100.80.0.7", iface: "lan0", table: 254},                     // CGNAT on the LAN: allowed
		{addr: "100.90.0.1", iface: "", restrict: true, relayDeny: true},    // blackhole (EINVAL): fail closed
		{addr: "100.91.0.1", iface: "", restrict: true, relayDeny: true},    // prohibit (EACCES): fail closed
		{addr: "100.100.1.2", iface: "lo", local: true, restrict: true, relayDeny: true},
		{addr: "192.0.2.10", iface: "lan0", table: 254},
		{addr: "198.51.100.1", iface: "", relayDeny: true}, // no route at all
	})
}

// TestDialInterfacePinsTheSocket binds to lo and reaches a loopback
// listener; bound to another interface the same address is unreachable,
// which IP_UNICAST_IF (the Python release) would not enforce for TCP.
func TestDialInterfacePinsTheSocket(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := netip.MustParseAddrPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	c, err := DialInterface(ctx, "lo", addr)
	if err != nil {
		t.Fatalf("bound to lo: %v", err)
	}
	_ = c.Close()
	if _, err := DialInterface(ctx, "webssh-no-such-if", addr); err == nil {
		t.Fatal("unknown interface accepted")
	}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		short, stop := context.WithTimeout(t.Context(), time.Second)
		c, err := DialInterface(short, i.Name, addr)
		stop()
		if err == nil {
			_ = c.Close()
			t.Fatalf("bound to %s, the loopback listener was reached", i.Name)
		}
		return
	}
	t.Log("no other interface is up; only the lo case ran")
}

// TestPythonRoutesInNamespace compares the kernel's answers through the
// Python release's lookup (testdata/python_routes.py, run by
// netns-test.sh in the same namespace) with LookupRoute. Python returns
// no interface for an IPv4-mapped address, whose route the kernel only
// knows in its IPv4 form; Go's callers unmap first, so that one entry is
// compared with the IPv4 route.
func TestPythonRoutesInNamespace(t *testing.T) {
	path := os.Getenv("WEBSSH_PY_ROUTES")
	if path == "" {
		t.Skip("run with testdata/netns-test.sh")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var python map[string]*string
	if err := json.Unmarshal(raw, &python); err != nil || len(python) < 10 {
		t.Fatalf("python routes: %v (%d)", err, len(python))
	}
	for text, want := range python {
		addr := netip.MustParseAddr(text)
		r, err := LookupRoute(t.Context(), addr)
		got := ""
		if err == nil {
			got = r.Interface
		}
		w := ""
		if want != nil {
			w = *want
		}
		if addr.Is4In6() {
			if w != "" {
				t.Errorf("%s: python found %q for a mapped address", text, w)
			}
			continue
		}
		if got != w {
			t.Errorf("%s: python %q, go %q (%v)", text, w, got, err)
		}
		t.Logf("%-28s python=%-10q go=%q", text, w, got)
	}
}
