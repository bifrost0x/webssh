package netpolicy

import (
	"context"
	"errors"
	"net/netip"
)

// ErrRouteUnsupported reports a platform without a kernel route lookup.
var ErrRouteUnsupported = errors.New("netpolicy: route lookup is not supported on this platform")

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
