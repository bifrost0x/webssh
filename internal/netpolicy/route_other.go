//go:build !linux

package netpolicy

import (
	"context"
	"net"
	"net/netip"
	"time"
)

func lookupRoute(context.Context, netip.Addr) (Route, error) {
	return Route{}, ErrRouteUnsupported
}

// interfaceDialer is not available: without SO_BINDTODEVICE a connection
// cannot be held on the tailnet interface, so Tailscale SSH is refused, as
// the Python release refused it outside Linux.
func interfaceDialer(string, time.Duration) (*net.Dialer, error) {
	return nil, ErrInterfaceUnsupported
}
