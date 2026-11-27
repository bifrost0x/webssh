package terminal

import (
	"context"
	"errors"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// reasonTailnet is the reason the owner sees when turning the tailnet
// block on ends a session (app/tailscale_ssh.py).
const reasonTailnet = "This host is on the tailnet and requires Tailscale SSH"

// errTailnetRoute refuses a terminal.open whose route the tailnet block,
// turned on while it was under way, no longer allows.
var errTailnetRoute = fault.New(fault.TargetBlocked, reasonTailnet+".")

// errPassMoved tells registerOpened that a CloseRestrictedRoutes pass
// began after the attempt did.
var errPassMoved = errors.New("terminal: tailnet pass moved")

// routeCheckTimeout bounds the route check of one late attempt.
const routeCheckTimeout = 10 * time.Second

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
	// An attempt that registers after this point checks its route itself
	// (registerOpened).
	m.tailnetPass++
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

// registerOpened registers the session of a terminal.open. A
// CloseRestrictedRoutes pass that began while the attempt was under way
// (for example while a host key prompt was open) did not see the session,
// so its route is checked against the policy as it is now before it is
// registered; the check runs without the lock and repeats if a further
// pass began meanwhile. A Tailscale SSH session is exempt as in the pass.
func (m *Manager) registerOpened(ctx context.Context, s *Session, att *attempt) error {
	pass := att.pass
	for {
		err := m.registerAt(s, att.gen, &pass)
		if !errors.Is(err, errPassMoved) {
			return err
		}
		if route, ok := s.netRoute(); ok && m.lateRouteRestricted(ctx, route) {
			return errTailnetRoute
		}
	}
}

func (m *Manager) lateRouteRestricted(ctx context.Context, route client.Route) bool {
	if m.routeRestricted == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), routeCheckTimeout)
	defer cancel()
	return m.routeRestricted(ctx, route)
}
