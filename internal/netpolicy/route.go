package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// ErrRouteUnsupported reports a platform without a kernel route lookup.
var ErrRouteUnsupported = errors.New("netpolicy: route lookup is not supported on this platform")

// ErrInterfaceUnsupported reports a platform that cannot bind a socket to
// one interface.
var ErrInterfaceUnsupported = errors.New("netpolicy: interface pinning is not supported on this platform")

// Route is the kernel's answer to "which interface would this address use".
type Route struct {
	Interface string // output interface name, "lo" for local addresses
	Local     bool   // RTN_LOCAL: the address belongs to this host
	Table     uint32 // routing table that matched, 52 for tailscaled routes
}

// RouteLookup asks the kernel FIB for the route to one exact address.
// LookupRoute is the production implementation; tests inject their own.
type RouteLookup func(ctx context.Context, addr netip.Addr) (Route, error)

// LookupRoute runs one bounded FIB lookup. On Linux it is a single
// RTM_GETROUTE request (route_linux.go); elsewhere it returns
// ErrRouteUnsupported.
func LookupRoute(ctx context.Context, addr netip.Addr) (Route, error) {
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	return lookupRoute(ctx, addr)
}

// DialInterface connects to addr with the socket bound to the interface
// name (SO_BINDTODEVICE on Linux; ErrInterfaceUnsupported elsewhere). It
// is the connection of Tailscale SSH, whose address the tailscale policy
// pinned after the route check; the outbound policy does not apply.
func DialInterface(ctx context.Context, name string, addr netip.AddrPort) (net.Conn, error) {
	d, err := interfaceDialer(name, 0)
	if err != nil {
		return nil, err
	}
	network := "tcp4"
	if addr.Addr().Is6() {
		network = "tcp6"
	}
	return d.DialContext(ctx, network, addr.String())
}
