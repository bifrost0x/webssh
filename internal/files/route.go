package files

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// errTailnetRoute refuses a source whose route the tailnet block, turned
// on while it was being opened, no longer allows.
var errTailnetRoute = fault.New(fault.TargetBlocked, "This host is on the tailnet and requires Tailscale SSH.")

// errPassMoved tells Slot.add that a CloseRestrictedRoutes pass began
// after the slot was reserved.
var errPassMoved = errors.New("files: tailnet pass moved")

// routeCheckTimeout bounds the route check of one late source.
const routeCheckTimeout = 10 * time.Second

// tailnetClosable reports the kinds CloseRestrictedRoutes closes.
func tailnetClosable(kind SourceKind) bool {
	return kind != SourceSFTPSession && kind != SourceSMBQuick
}

// Routed is implemented by backends on a known network path: the address
// the connection was pinned to and what each relay was asked to reach
// (client.Route). ok is false for a path outside the network policy
// (Tailscale SSH).
type Routed interface {
	Route() (peer netip.Addr, onward []string, ok bool)
}

// CloseRestrictedRoutes closes the Quick SFTP sources whose route
// restricted reports at once, held or not, as a revocation does
// (close_connections_where). Terminal session sources end with their
// session; backends without a known route stay. SMB sources stay: the
// tailnet rule is about SSH to tailnet nodes and never applied to SMB, in
// the Python release as here. restricted runs without
// registry locks, because it may query the kernel route table. It returns
// the number of sources it closed.
func (r *Registry) CloseRestrictedRoutes(restricted func(peer netip.Addr, onward []string) bool) int {
	type candidate struct {
		s      *source
		peer   netip.Addr
		onward []string
	}
	var all []candidate
	r.mu.Lock()
	// A source inserted after this point checks its route itself
	// (Slot.add).
	r.tailnetPass++
	for _, s := range r.sources {
		if s.closed || !tailnetClosable(s.kind) {
			continue
		}
		if routed, ok := s.backend.(Routed); ok {
			if peer, onward, known := routed.Route(); known {
				all = append(all, candidate{s, peer, onward})
			}
		}
	}
	r.mu.Unlock()
	matched := map[*source]bool{}
	for _, c := range all {
		if restricted(c.peer, c.onward) {
			matched[c.s] = true
		}
	}
	if len(matched) == 0 {
		return 0
	}
	closed := 0
	r.closeWhere(true, func(s *source) bool {
		if matched[s] {
			closed++
			return true
		}
		return false
	})
	return closed
}

func (r *Registry) passNow() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tailnetPass
}

// passMoved runs with r.mu held: true, and pass updated, when pass is set
// for a kind the pass closes and is not the current pass.
func (r *Registry) passMoved(kind SourceKind, pass *uint64) bool {
	if pass == nil || !tailnetClosable(kind) || *pass == r.tailnetPass {
		return false
	}
	*pass = r.tailnetPass
	return true
}

// lateRouteRestricted decides b as CloseRestrictedRoutes would: a backend
// without a known route stays, a known route is asked of the policy as it
// is now, and without RouteRestricted it is refused (fail closed).
func (r *Registry) lateRouteRestricted(b Backend) bool {
	routed, ok := b.(Routed)
	if !ok {
		return false
	}
	peer, onward, known := routed.Route()
	if !known {
		return false
	}
	if r.opts.RouteRestricted == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), routeCheckTimeout)
	defer cancel()
	return r.opts.RouteRestricted(ctx, peer, onward)
}
