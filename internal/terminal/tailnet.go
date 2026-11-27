package terminal

import (
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// reasonTailnet is the reason the owner sees when turning the tailnet
// block on ends a session (app/tailscale_ssh.py).
const reasonTailnet = "This host is on the tailnet and requires Tailscale SSH"

// CloseRestrictedRoutes ends every live session whose route restricted
// reports, the way AdminDisconnect does: a tmux session stays on the host,
// its row is marked not connected and the attached pages learn the
// reason. Tailscale SSH sessions are exempt. A session without a
// connection of its own is asked with the zero Route, which the network
// policy treats as an unknown address. restricted runs without manager
// locks, because it may query the kernel route table. It returns the
// number of sessions it ended.
func (m *Manager) CloseRestrictedRoutes(restricted func(client.Route) bool) int {
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	closed := 0
	for _, s := range all {
		route, ok := s.netRoute()
		if ok && restricted(route) && s.terminate(reasonTailnet, nil) {
			closed++
		}
	}
	return closed
}

// netRoute is the route of the session's connection; ok is false for a
// Tailscale SSH session.
func (s *Session) netRoute() (client.Route, bool) {
	info, _ := s.snapshot()
	if info.AuthType == protocol.AuthTailscale {
		return client.Route{}, false
	}
	if s.host == nil {
		return client.Route{}, true
	}
	return s.host.netRoute()
}
