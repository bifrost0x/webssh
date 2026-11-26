//go:build !linux

package netpolicy

import (
	"context"
	"net/netip"
)

func lookupRoute(context.Context, netip.Addr) (Route, error) {
	return Route{}, ErrRouteUnsupported
}
