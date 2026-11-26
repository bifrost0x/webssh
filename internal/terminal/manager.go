package terminal

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Deps are the collaborators of the terminal. Shells and Log are required.
type Deps struct {
	Shells Shells
	// Profiles resolves saved hosts; without it terminal.open with a
	// profile_id answers not_available_in_preview.
	Profiles Profiles
	// Routes resolves saved jump hosts and SOCKS5 proxies of a connection
	// typed by hand; without it such a connection answers
	// not_available_in_preview.
	Routes SavedRoutes
	Log    *slog.Logger
}

// Manager owns every terminal session of the process. The composition
// root mounts Routes on the realtime endpoint and installs HandleBinary,
// the manager as Restorer, Keepalive with OnKeepalive, PeerClosed with
// OnClose and Revoked as a subscriber of session revocations.
type Manager struct {
	cfg      Config
	shells   Shells
	profiles Profiles
	routes   SavedRoutes
	log      *slog.Logger
	now      func() time.Time

	flow    *ledger
	input   *inputBudget
	quota   *quota
	prompts *prompts

	mu       sync.Mutex
	sessions map[string]*Session
	peers    map[uint64]*peerState
	attempts map[attemptKey]*attempt
	stopping bool

	wg   sync.WaitGroup
	stop chan struct{}
	once sync.Once
}

// New validates the dependencies and starts the sweeper of idle sessions
// and stalled streams. Stop it with Shutdown.
func New(cfg Config, deps Deps) (*Manager, error) {
	if deps.Shells == nil || deps.Log == nil {
		return nil, errors.New("terminal: shells and logger are required")
	}
	cfg.defaults()
	m := &Manager{
		cfg: cfg, shells: deps.Shells, profiles: deps.Profiles, routes: deps.Routes, log: deps.Log, now: time.Now,
		flow: newLedger(cfg.Flow), input: newInputBudget(cfg.Input),
		quota:    newQuota(cfg.SessionsGlobal, cfg.SessionsPerUser),
		prompts:  newPrompts(cfg.MaxPrompts),
		sessions: map[string]*Session{}, peers: map[uint64]*peerState{}, attempts: map[attemptKey]*attempt{},
		stop: make(chan struct{}),
	}
	m.wg.Go(m.sweep)
	return m, nil
}

// spawn runs f in a goroutine the manager waits for in Shutdown. After
// Shutdown began, f runs in the caller, so no goroutine starts once the
// wait is under way.
func (m *Manager) spawn(f func()) {
	m.mu.Lock()
	if m.stopping {
		m.mu.Unlock()
		f()
		return
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		f()
	}()
}

// lookup returns a live session of owner. Sessions of other users are
// reported as missing.
func (m *Manager) lookup(owner int64, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.owner != owner {
		return nil, fault.New(fault.NotFound, "Session not found.")
	}
	return s, nil
}

// sessionsOf lists the live sessions of owner, oldest first.
func (m *Manager) sessionsOf(owner int64) []*Session {
	m.mu.Lock()
	list := make([]*Session, 0, 4)
	for _, s := range m.sessions {
		if s.owner == owner {
			list = append(list, s)
		}
	}
	m.mu.Unlock()
	slices.SortFunc(list, func(a, b *Session) int { return a.created.Compare(b.created) })
	return list
}

func (m *Manager) remove(s *Session) {
	m.mu.Lock()
	if m.sessions[s.id] == s {
		delete(m.sessions, s.id)
	}
	m.mu.Unlock()
	m.input.forget(s.id)
}

// Restorable lists the sessions of p for hello, so a reloaded page can
// attach to them (realtime.Restorer).
func (m *Manager) Restorable(_ context.Context, p principal.Principal) ([]protocol.SessionInfo, error) {
	list := m.sessionsOf(p.UserID)
	out := make([]protocol.SessionInfo, 0, len(list))
	for _, s := range list {
		if info, ok := s.snapshot(); ok {
			out = append(out, info)
		}
	}
	return out, nil
}

// Keepalive records activity for every session of the peer's user, as
// the keep_alive event of the Python release did. It runs on the read
// loop and only takes short locks.
func (m *Manager) Keepalive(peer protocol.Peer) {
	now := m.now()
	for _, s := range m.sessionsOf(peer.Principal().UserID) {
		s.touch(now)
	}
}

// endsTerminals are the revocation reasons after which the Python release
// closed every SSH session of the user (user_lifecycle.revoke_user_access:
// sign-out, password change, factor reset, lock, role change). Ending a
// login from the session list or by expiry leaves the user's terminals
// running, as before.
var endsTerminals = []principal.Reason{
	principal.ReasonLogout, principal.ReasonPasswordChanged, principal.ReasonFactorChanged,
	principal.ReasonAccountLocked, principal.ReasonRoleChanged,
}

// Revoked reacts to an ended browser session. The realtime endpoint has
// already cancelled the session's connections, so their streams stop at
// once; for the reasons above every SSH session and pending connection
// attempt of the user ends as well. It does not block.
func (m *Manager) Revoked(rev principal.Revocation) {
	if !slices.Contains(endsTerminals, rev.Reason) || rev.UserID <= 0 {
		return
	}
	m.cancelAttemptsOf(func(k attemptKey, a *attempt) bool { return a.owner == rev.UserID })
	for _, s := range m.sessionsOf(rev.UserID) {
		s.terminate(reasonClosed, nil)
	}
}

// sweep detaches streams whose oldest frame is overdue and enforces the
// idle timeout.
func (m *Manager) sweep() {
	t := time.NewTicker(m.cfg.SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			now := m.now()
			for _, a := range m.allAttachments() {
				if m.flow.stale(a.credit, now) {
					m.detach(a, "backpressure")
				}
			}
			m.checkIdle(now)
		}
	}
}

// checkIdle warns once IdleWarning before the timeout and closes sessions
// idle for IdleTimeout. Activity after a warning re-arms it.
func (m *Manager) checkIdle(now time.Time) {
	m.mu.Lock()
	list := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		list = append(list, s)
	}
	m.mu.Unlock()
	for _, s := range list {
		switch s.idleState(now, m.cfg.IdleTimeout, m.cfg.IdleWarning) {
		case idleExpired:
			s.terminate(reasonClosed, nil)
		case idleWarn:
			s.broadcast(protocol.TypeTerminalTimeoutWarn, protocol.TerminalTimeoutWarning{SessionID: s.id})
		}
	}
}

// Shutdown refuses new sessions, cancels pending attempts, ends every
// session and waits for all goroutines of the terminal or for ctx.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.once.Do(func() {
		m.cancelAttemptsOf(func(attemptKey, *attempt) bool { return true })
		m.mu.Lock()
		m.stopping = true
		list := make([]*Session, 0, len(m.sessions))
		for _, s := range m.sessions {
			list = append(list, s)
		}
		m.mu.Unlock()
		close(m.stop)
		for _, s := range list {
			s.terminate(reasonClosed, nil)
		}
	})
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats is a snapshot for diagnostics and tests.
type Stats struct {
	Sessions       int
	Reserved       int // quota slots in use, attempts included
	Attachments    int
	InFlightBytes  int
	InFlightFrames int
}

// Stats returns counters of the capability.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	n := len(m.sessions)
	m.mu.Unlock()
	b, f := m.flow.inFlight()
	return Stats{Sessions: n, Reserved: m.quota.used(), Attachments: len(m.allAttachments()), InFlightBytes: b, InFlightFrames: f}
}
