package netpolicy

import (
	"context"
	"net/netip"
)

// TailnetRuleActive reports whether the tailnet rule applies now.
func (p *Policy) TailnetRuleActive() bool { return p.cfg.Tailnet.active() }

// OpenRouteRestricted reports whether an open ordinary connection uses a
// route the tailnet rule now refuses (open_route_restricted of the Python
// release). peer is the address the connection was pinned to: the target,
// or the first jump host or SOCKS5 proxy; onward lists what each relay was
// asked to reach, further jump hosts first and the target last. The checks
// are those a new connection passes: peer as a target, peer as a relay
// when there is an onward destination, further jump hosts as relays and
// every destination as an address or as a name the relay resolves. An
// unknown peer or a malformed destination counts as restricted; a further
// jump host given by name does too, because a new connection resolves it
// here while the rule applies.
func (p *Policy) OpenRouteRestricted(ctx context.Context, peer netip.Addr, onward []string) bool {
	t := p.cfg.Tailnet
	if !t.active() {
		return false
	}
	if !peer.IsValid() || t.targetRestricted(ctx, peer) {
		return true
	}
	if len(onward) == 0 {
		return false
	}
	if t.relayRestricted(ctx, peer) {
		return true
	}
	for i, dest := range onward {
		canonical, err := CanonicalHost(dest)
		if err != nil {
			return true
		}
		relay := i < len(onward)-1
		addr, literal := policyAddr(canonical)
		switch {
		case literal && (t.targetRestricted(ctx, addr) || relay && t.relayRestricted(ctx, addr)):
			return true
		case !literal && (relay || t.remoteNameRestricted(ctx, canonical, p.lookup)):
			return true
		}
	}
	return false
}
