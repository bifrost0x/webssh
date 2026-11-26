package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

var (
	tailnetV4   = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6   = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	tailnet4via = netip.MustParsePrefix("fd7a:115c:a1e0:b1a::/64")
)

// NodeAddress reports whether addr is a tailnet node address and returns it
// in its routed form. An IPv4-mapped address counts as its IPv4 form
// (::ffff:100.64.0.1 is a node address): a dual-stack socket sends it over
// IPv4. 4via6 subnet routes lie inside the node range but reach hosts with
// their own sshd.
func NodeAddress(addr netip.Addr) (netip.Addr, bool) {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || tailnet4via.Contains(addr) {
		return netip.Addr{}, false
	}
	if tailnetV4.Contains(addr) || tailnetV6.Contains(addr) {
		return addr, true
	}
	return netip.Addr{}, false
}

// Tailnet configures the tailnet rule: ordinary SSH to a tailnet node is
// refused, because tailssh authorizes the connecting node and not the
// offered credential, so the connection would run under the shared node
// identity outside every Tailscale SSH allowlist.
//
// Unlike the Python release the rule does not depend on the Tailscale SSH
// switch (D-28): it applies whenever this host is a tailnet node, which is
// the case when the tailnet interface exists, and always while the
// Tailscale SSH feature is on (as before).
type Tailnet struct {
	// Restricted reports the admin setting
	// tailscale_ssh_restrict_tailnet_routes. Nil means restricted.
	Restricted func() bool
	// Interface is TAILSCALE_SSH_INTERFACE; empty turns the rule off, as
	// in Python.
	Interface string
	// FeatureEnabled is TAILSCALE_SSH_ENABLED.
	FeatureEnabled bool

	// Lookup and InterfacePresent replace the kernel in tests.
	Lookup           RouteLookup
	InterfacePresent func(name string) bool
}

func (t Tailnet) iface() string { return strings.TrimSpace(t.Interface) }

func (t Tailnet) present(name string) bool {
	if t.InterfacePresent != nil {
		return t.InterfacePresent(name)
	}
	_, err := net.InterfaceByName(name)
	return err == nil
}

// active reports whether the rule applies now.
func (t Tailnet) active() bool {
	if t.Restricted != nil && !t.Restricted() {
		return false
	}
	name := t.iface()
	if name == "" {
		return false
	}
	return t.FeatureEnabled || t.present(name)
}

func (t Tailnet) lookup(ctx context.Context, addr netip.Addr) (Route, error) {
	if t.Lookup != nil {
		return t.Lookup(ctx, addr)
	}
	return LookupRoute(ctx, addr)
}

// unknownRoute decides a failed lookup. It fails closed, except where the
// platform has no route lookup and the tailnet interface does not exist:
// then this host is not a tailnet node.
func (t Tailnet) unknownRoute(err error) bool {
	if errors.Is(err, ErrRouteUnsupported) {
		return t.present(t.iface())
	}
	return true
}

// targetRestricted reports whether an ordinary connection to addr must be
// refused: a node address whose route uses the tailnet interface, this
// host's own address (local route) or an unknown route. A 100.64.0.0/10
// address routed through another interface, such as carrier-grade NAT on
// the local network, stays reachable.
func (t Tailnet) targetRestricted(ctx context.Context, addr netip.Addr) bool {
	node, ok := NodeAddress(addr)
	if !ok || !t.active() {
		return false
	}
	route, err := t.lookup(ctx, node)
	if err != nil {
		return t.unknownRoute(err)
	}
	return route.Local || route.Interface == "lo" || route.Interface == t.iface()
}

// relayRestricted reports whether a jump host or SOCKS5 proxy at addr
// shares this host's network namespace (loopback, unspecified or one of its
// own addresses), so its onward connections would leave with the node
// identity. A relay on a node address is refused by targetRestricted.
func (t Tailnet) relayRestricted(ctx context.Context, addr netip.Addr) bool {
	if !t.active() {
		return false
	}
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
		return true
	}
	route, err := t.lookup(ctx, addr)
	if err != nil {
		return t.unknownRoute(err)
	}
	return route.Local || route.Interface == "lo"
}

// remoteNameRestricted reports whether a name that a relay will resolve
// leads onto the tailnet: MagicDNS names always, other names when the local
// resolver returns a restricted node address. A name that does not resolve
// here stays allowed for the remote side, as in Python.
func (t Tailnet) remoteNameRestricted(ctx context.Context, canonical string, resolve func(context.Context, string) ([]netip.Addr, error)) bool {
	if !t.active() {
		return false
	}
	if canonical == "ts.net" || strings.HasSuffix(canonical, ".ts.net") {
		return true
	}
	candidates, err := resolve(ctx, canonical)
	if err != nil {
		return false
	}
	for _, candidate := range candidates {
		if t.targetRestricted(ctx, candidate) {
			return true
		}
	}
	return false
}
