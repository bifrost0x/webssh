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

// TestUpgradedInstallationFollowsTheSwitch is D-28 under D-01: an
// installation upgraded from the Python release keeps its behaviour (the
// rule only with Tailscale SSH on) and is warned while the tailnet
// interface exists; without the derived setting the rule applies.
func TestUpgradedInstallationFollowsTheSwitch(t *testing.T) {
	addr := netip.MustParseAddr("100.100.100.10")
	follows := true
	legacy := Tailnet{Interface: "tailscale0", Lookup: labRoutes.lookup, InterfacePresent: func(string) bool { return true },
		FollowsSwitch: func() bool { return follows }}
	if legacy.targetRestricted(t.Context(), addr) || legacy.relayRestricted(t.Context(), netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("upgraded installation with Tailscale SSH off: ordinary SSH to the node must stay possible")
	}
	if !legacy.LegacyGap() {
		t.Fatal("the gap is not reported for the warning")
	}
	configured := legacy
	configured.InterfacePresent = func(string) bool { return false }
	configured.InterfaceConfigured = true
	if configured.targetRestricted(t.Context(), addr) || !configured.LegacyGap() {
		t.Fatal("an explicitly configured interface follows the switch as well")
	}
	on := legacy
	on.FeatureEnabled = true
	if !on.targetRestricted(t.Context(), addr) || on.LegacyGap() {
		t.Fatal("with Tailscale SSH on the rule applies, as in Python")
	}
	noNode := legacy
	noNode.InterfacePresent = func(string) bool { return false }
	if noNode.LegacyGap() {
		t.Fatal("no interface, no gap")
	}
	lifted := legacy
	lifted.Restricted = func() bool { return false }
	if lifted.LegacyGap() {
		t.Fatal("the administrator lifted the rule on purpose; no warning")
	}
	follows = false
	if !legacy.targetRestricted(t.Context(), addr) || legacy.LegacyGap() {
		t.Fatal("after the administrator turns the derived setting off the rule applies")
	}
	fresh := legacy
	fresh.FollowsSwitch = nil
	if !fresh.targetRestricted(t.Context(), addr) || fresh.LegacyGap() {
		t.Fatal("a new installation has the rule")
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

// tailscaled in userspace networking has no interface: a configured
// TAILSCALE_SSH_INTERFACE keeps the rule active, so a loopback relay
// (tailscaled's own SOCKS5 proxy) is refused.
func TestTailnetRuleWithConfiguredInterfaceButNoDevice(t *testing.T) {
	r := Tailnet{Interface: "tailscale0", InterfaceConfigured: true, Lookup: labRoutes.lookup, InterfacePresent: func(string) bool { return false }}
	if !r.relayRestricted(t.Context(), netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback relay allowed in userspace mode")
	}
	r.InterfaceConfigured = false
	if r.relayRestricted(t.Context(), netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("the default interface name alone must not restrict a host without it")
	}
}

// NAT64 addresses carry an IPv4 address; a tailnet node behind the
// well-known prefix is a node address, and it is restricted unless its
// route leaves through another interface (a NAT64 gateway on the LAN).
func TestNodeAddressBehindNAT64(t *testing.T) {
	got, ok := NodeAddress(netip.MustParseAddr("64:ff9b::100.100.100.10"))
	if !ok || got != netip.MustParseAddr("100.100.100.10") {
		t.Fatalf("got %v %v", got, ok)
	}
	if !rule(true).targetRestricted(t.Context(), netip.MustParseAddr("64:ff9b::100.100.100.10")) {
		t.Fatal("tailnet node behind NAT64 with unknown route allowed")
	}
	for _, s := range []string{"64:ff9b::8.8.8.8", "64:ff9b::10.0.0.1", "64:ff9b::127.0.0.1"} {
		if !Internal(netip.MustParseAddr(s)) {
			t.Errorf("%s is not internal", s)
		}
	}
}
