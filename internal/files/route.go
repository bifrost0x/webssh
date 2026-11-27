package files

import "net/netip"

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
	for _, s := range r.sources {
		if s.closed || s.kind == SourceSFTPSession || s.kind == SourceSMBQuick {
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
