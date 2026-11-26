//go:build linux

package netpolicy

import (
	"context"
	"errors"
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
