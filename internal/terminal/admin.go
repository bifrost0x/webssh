package terminal

import (
	"slices"
	"strconv"
	"time"
)

// reasonAdmin is the reason the owner sees when an administrator ends a
// session (app/operations.py).
const reasonAdmin = "Administrator disconnected SSH connection"

// AdminSession is one live session as the instance status lists it.
type AdminSession struct {
	ID      string
	Owner   int64
	Target  string // user@host:port
	Tmux    bool
	Created time.Time
}

// AdminSessions lists the live sessions of every user, oldest first,
// without touching their connections (admin_session_snapshot).
func (m *Manager) AdminSessions() []AdminSession {
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	out := make([]AdminSession, 0, len(all))
	for _, s := range all {
		info, live := s.snapshot()
		if !live {
			continue
		}
		port := info.Port
		if port == 0 {
			port = 22
		}
		out = append(out, AdminSession{ID: s.id, Owner: s.owner, Tmux: s.tmux != nil, Created: s.created,
			Target: info.Username + "@" + info.Host + ":" + strconv.Itoa(port)})
	}
	slices.SortStableFunc(out, func(a, b AdminSession) int { return a.Created.Compare(b.Created) })
	return out
}

// AdminDisconnect ends session id of any user for an administrator. A
// tmux session behind it stays on the host for a later reattach: an
// administrator must not end remote workloads. The attached pages learn
// the reason. It reports whether the session was still live.
func (m *Manager) AdminDisconnect(id string) bool {
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	return ok && s.terminate(reasonAdmin, nil)
}
