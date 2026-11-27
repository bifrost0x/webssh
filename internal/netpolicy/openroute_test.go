package netpolicy

import (
	"net/netip"
	"sync/atomic"
	"testing"
)

// OpenRouteRestricted applies to an open connection the checks a new one
// passes now (open_route_restricted): the pinned peer as a target, as a
// relay when there is an onward destination, and every onward destination
// as an address or as a name a relay resolves. An unknown peer fails
// closed; with the rule lifted nothing is restricted.
func TestOpenRouteRestricted(t *testing.T) {
	var restrict atomic.Bool
	p, _, _ := newTestPolicy(t, Config{Tailnet: Tailnet{FeatureEnabled: true, Restricted: restrict.Load}})
	addr := netip.MustParseAddr
	tests := []struct {
		why    string
		peer   netip.Addr
		onward []string
		want   bool
	}{
		{"unknown peer", netip.Addr{}, nil, true},
		{"tailnet node", addr("100.100.100.10"), nil, true},
		{"own tailnet address", addr("100.100.100.2"), nil, true},
		{"node range, route unknown", addr("100.99.0.1"), nil, true},
		{"LAN host", addr("192.168.1.10"), nil, false},
		{"own LAN address as target", addr("192.168.1.2"), nil, false},
		{"CGNAT on the LAN", addr("100.80.0.1"), nil, false},
		{"jump host on the LAN to a LAN host", addr("192.168.1.10"), []string{"192.168.1.10"}, false},
		{"jump host to a tailnet node", addr("192.168.1.10"), []string{"100.100.100.10"}, true},
		{"jump host to a MagicDNS name", addr("192.168.1.10"), []string{"box.tail1234.ts.net"}, true},
		{"jump host to a name of a node", addr("192.168.1.10"), []string{"node.example"}, true},
		{"jump host to a name resolved remotely", addr("192.168.1.10"), []string{"only-remote.corp"}, false},
		{"jump host to a LAN name", addr("192.168.1.10"), []string{"lan.example"}, false},
		{"loopback proxy (tailscaled)", addr("127.0.0.1"), []string{"192.168.1.10"}, true},
		{"relay on this host", addr("192.168.1.2"), []string{"192.168.1.10"}, true},
		{"relay with unknown route", addr("203.0.113.9"), []string{"192.168.1.10"}, true},
		{"further jump host on loopback", addr("192.168.1.10"), []string{"127.0.0.1", "192.168.1.10"}, true},
		{"further jump host by name", addr("192.168.1.10"), []string{"lan.example", "192.168.1.10"}, true},
		{"chain of LAN hosts", addr("192.168.1.10"), []string{"192.168.1.10", "192.168.1.10"}, false},
		{"malformed destination", addr("192.168.1.10"), []string{"bad host"}, true},
	}
	restrict.Store(true)
	if !p.TailnetRuleActive() {
		t.Fatal("the rule is not active")
	}
	for _, tt := range tests {
		if got := p.OpenRouteRestricted(t.Context(), tt.peer, tt.onward); got != tt.want {
			t.Errorf("%s: OpenRouteRestricted(%v, %q) = %v, want %v", tt.why, tt.peer, tt.onward, got, tt.want)
		}
	}
	restrict.Store(false)
	if p.TailnetRuleActive() {
		t.Fatal("the rule is active with the block lifted")
	}
	for _, tt := range tests {
		if p.OpenRouteRestricted(t.Context(), tt.peer, tt.onward) {
			t.Errorf("%s: restricted with the block lifted", tt.why)
		}
	}
}
