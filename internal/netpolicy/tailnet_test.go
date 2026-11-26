package netpolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// fakeRoutes answers lookups from a table; missing entries fail like
// ENETUNREACH.
type fakeRoutes map[string]Route

func (f fakeRoutes) lookup(_ context.Context, addr netip.Addr) (Route, error) {
	if r, ok := f[addr.String()]; ok {
		return r, nil
	}
	return Route{}, errors.New("network unreachable")
}

var labRoutes = fakeRoutes{
	"100.100.100.10":    {Interface: "tailscale0", Table: 52},
	"100.100.100.2":     {Interface: "lo", Local: true, Table: 255},
	"100.80.0.1":        {Interface: "eth1", Table: 254}, // CGNAT on the LAN
	"fd7a:115c:a1e0::5": {Interface: "tailscale0", Table: 52},
	"192.168.1.10":      {Interface: "eth0", Table: 254},
	"192.168.1.2":       {Interface: "lo", Local: true, Table: 255},
}

func rule(restrict bool) Tailnet {
	return Tailnet{
		Restricted: func() bool { return restrict }, Interface: "tailscale0",
		FeatureEnabled: true, Lookup: labRoutes.lookup,
	}
}

func TestNodeAddress(t *testing.T) {
	tests := map[string]bool{
		"100.64.0.0":                true,
		"100.127.255.255":           true,
		"100.63.255.255":            false,
		"100.128.0.0":               false,
		"::ffff:100.100.100.10":     true,
		"fd7a:115c:a1e0::1":         true,
		"fd7a:115c:a1e0:ab12::1":    true,
		"fd7a:115c:a1e0:b1a::a00:1": false, // 4via6
		"fd7a:115c:a1e1::1":         false,
		"10.0.0.1":                  false,
		"fe80::1%tailscale0":        false,
	}
	for in, want := range tests {
		if _, got := NodeAddress(netip.MustParseAddr(in)); got != want {
			t.Errorf("NodeAddress(%s) = %v, want %v", in, got, want)
		}
	}
	if got, _ := NodeAddress(netip.MustParseAddr("::ffff:100.100.100.10")); !got.Is4() {
		t.Error("mapped address must be returned as IPv4")
	}
}

func TestTargetRestricted(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		addr string
		want bool
		why  string
	}{
		{"100.100.100.10", true, "node routed via tailscale0 (table 52)"},
		{"::ffff:100.100.100.10", true, "mapped form uses the IPv4 route"},
		{"100.100.100.2", true, "own tailnet address routes via lo"},
		{"fd7a:115c:a1e0::5", true, "IPv6 node"},
		{"fd7a:115c:a1e0::6", true, "node range, route unknown: fail closed"},
		{"100.99.0.1", true, "node range, route unknown: fail closed"},
		{"100.80.0.1", false, "CGNAT on another interface"},
		{"192.168.1.10", false, "not a node address"},
		{"192.168.1.2", false, "own LAN address is not a node address"},
		{"fd7a:115c:a1e0:b1a::a00:1", false, "4via6 subnet route"},
	}
	for _, tt := range tests {
		if got := rule(true).targetRestricted(ctx, netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("%s (%s): got %v", tt.addr, tt.why, got)
		}
		if rule(false).targetRestricted(ctx, netip.MustParseAddr(tt.addr)) {
			t.Errorf("%s restricted although the admin lifted the block", tt.addr)
		}
	}
	empty := Tailnet{Interface: "  ", FeatureEnabled: true, Lookup: labRoutes.lookup}
	if empty.targetRestricted(ctx, netip.MustParseAddr("100.100.100.10")) {
		t.Error("empty interface keeps Python semantics: rule inactive")
	}
}

// D-28: the rule applies whenever this host is a tailnet node (the
// interface exists), whether or not the Tailscale SSH feature is on. A
// host without the interface and without the feature is no node.
func TestTailnetRuleIndependentOfFeatureSwitch(t *testing.T) {
	addr := netip.MustParseAddr("100.100.100.10")
	node := Tailnet{Interface: "tailscale0", Lookup: labRoutes.lookup, InterfacePresent: func(string) bool { return true }}
	if !node.targetRestricted(t.Context(), addr) {
		t.Fatal("tailnet node with the feature off must be restricted")
	}
	if !node.relayRestricted(t.Context(), netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback relay on a tailnet node must be restricted")
	}
	plain := node
	plain.InterfacePresent = func(string) bool { return false }
	if plain.targetRestricted(t.Context(), addr) || plain.relayRestricted(t.Context(), netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("a host without the tailnet interface is no node: nothing to restrict")
	}
	plain.FeatureEnabled = true
	if !plain.targetRestricted(t.Context(), addr) {
		t.Fatal("with the feature on the rule applies as in Python")
	}
	lifted := node
	lifted.Restricted = func() bool { return false }
	if lifted.targetRestricted(t.Context(), addr) {
		t.Fatal("the admin setting lifts the rule")
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	unsupported := func(context.Context, netip.Addr) (Route, error) { return Route{}, ErrRouteUnsupported }
	addr := netip.MustParseAddr("100.100.100.10")
	present := Tailnet{Interface: "tailscale0", FeatureEnabled: true, Lookup: unsupported,
		InterfacePresent: func(string) bool { return true }}
	absent := present
	absent.InterfacePresent = func(string) bool { return false }
	if !present.targetRestricted(t.Context(), addr) {
		t.Error("interface present, no lookup: must fail closed")
	}
	if absent.targetRestricted(t.Context(), addr) {
		t.Error("no tailnet interface: host is no node, CGNAT stays reachable")
	}
}

func TestRelayRestricted(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1":        true,
		"::1":              true,
		"0.0.0.0":          true,
		"::ffff:127.0.0.1": true,
		"192.168.1.2":      true,  // own address via lo
		"192.168.1.10":     false, // ordinary LAN bastion
		"203.0.113.9":      true,  // route unknown: fail closed
	}
	for in, want := range tests {
		if got := rule(true).relayRestricted(t.Context(), netip.MustParseAddr(in)); got != want {
			t.Errorf("RelayRestricted(%s) = %v, want %v", in, got, want)
		}
		if rule(false).relayRestricted(t.Context(), netip.MustParseAddr(in)) {
			t.Errorf("%s restricted with the block lifted", in)
		}
	}
}

func TestRemoteNameRestricted(t *testing.T) {
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "node.lan":
			return []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("100.100.100.10")}, nil
		case "plain.lan":
			return []netip.Addr{netip.MustParseAddr("192.168.1.10")}, nil
		}
		return nil, errors.New("no such host")
	}
	tests := map[string]bool{
		"box.tail1234.ts.net": true,
		"ts.net":              true,
		"node.lan":            true,
		"plain.lan":           false,
		"only-remote.corp":    false, // does not resolve here
	}
	for in, want := range tests {
		if got := rule(true).remoteNameRestricted(t.Context(), in, resolve); got != want {
			t.Errorf("RemoteNameRestricted(%q) = %v, want %v", in, got, want)
		}
	}
}
