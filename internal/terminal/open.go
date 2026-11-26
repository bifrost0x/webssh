package terminal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// attemptKey names a connection attempt: the request_id is chosen by the
// client and unique only on its connection.
type attemptKey struct {
	peer      uint64
	requestID string
}

type attemptState int

const (
	attemptPending attemptState = iota
	attemptCancelled
	attemptCommitted
)

// attempt is a terminal.open in progress. state is guarded by Manager.mu.
type attempt struct {
	owner  int64
	cancel context.CancelFunc
	state  attemptState
}

func (m *Manager) addAttempt(k attemptKey, owner int64, cancel context.CancelFunc) (*attempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return nil, fault.New(fault.Unavailable, "The server is shutting down.")
	}
	if m.attempts[k] != nil {
		return nil, fault.New(fault.Busy, "Connection request already in progress.")
	}
	a := &attempt{owner: owner, cancel: cancel}
	m.attempts[k] = a
	return a, nil
}

func (m *Manager) removeAttempt(k attemptKey, a *attempt) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.attempts[k] == a {
		delete(m.attempts, k)
	}
}

// commit is the point of no return: whichever of commit and cancel comes
// first wins (Python: commit_if_active).
func (m *Manager) commit(a *attempt) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.state != attemptPending {
		return false
	}
	a.state = attemptCommitted
	return true
}

func (m *Manager) cancelled(a *attempt) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return a.state == attemptCancelled
}

// cancelAttemptsOf cancels every pending attempt that match selects.
func (m *Manager) cancelAttemptsOf(match func(attemptKey, *attempt) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, a := range m.attempts {
		if a.state == attemptPending && match(k, a) {
			a.state = attemptCancelled
			a.cancel()
		}
	}
}

var errCancelled = fault.New(fault.Cancelled, "")

// open is terminal.open. The channel is claimed first, so a client that
// reuses a channel learns it at once and output of the new session is
// addressable before the result. Prompts go to this connection only.
func (m *Manager) open(ctx context.Context, peer protocol.Peer, req protocol.TerminalOpen) (protocol.TerminalOpened, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.TerminalOpened{}, err
	}
	freeChannel, err := m.reserve(peer, req.Ch)
	if err != nil {
		return protocol.TerminalOpened{}, err
	}
	defer freeChannel()
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	key := attemptKey{peer: peer.ID(), requestID: req.RequestID}
	att, err := m.addAttempt(key, p.UserID, cancel)
	if err != nil {
		return protocol.TerminalOpened{}, err
	}
	defer m.removeAttempt(key, att)

	target, err := m.resolve(actx, p.UserID, req.Target)
	if err != nil {
		return protocol.TerminalOpened{}, err
	}
	release, err := m.quota.reserve(p.UserID)
	if err != nil {
		return protocol.TerminalOpened{}, err
	}
	ix := &interaction{m: m, peer: peer, owner: p.UserID, requestID: req.RequestID}
	sh, err := m.shells.OpenShell(actx, target, ix, req.Rows, req.Cols)
	if err != nil {
		release()
		if m.cancelled(att) {
			return protocol.TerminalOpened{}, errCancelled
		}
		return protocol.TerminalOpened{}, err
	}
	if !m.commit(att) || peer.Context().Err() != nil {
		release()
		m.spawn(func() { _ = sh.Close() })
		return protocol.TerminalOpened{}, errCancelled
	}
	s := m.newSession(p.UserID, sh, sessionInfo(target), release)
	if err := m.register(s); err != nil {
		release()
		m.spawn(func() { _ = sh.Close() })
		return protocol.TerminalOpened{}, err
	}
	// Bind before the loops start: nothing is read yet, so the first
	// output goes live to the channel without a replay.
	_, attachErr := m.attach(peer, s, req.Ch, 0, true)
	s.start(notice(target, req.Target))
	if attachErr != nil {
		s.terminate(reasonClosed, nil)
		return protocol.TerminalOpened{}, attachErr
	}
	info, _ := s.snapshot()
	return protocol.TerminalOpened{SessionID: s.id, Info: info}, nil
}

// cancelOpen is terminal.cancel: ok when the attempt was cancelled,
// not_found without such an attempt on this connection, conflict when it
// already produced its session.
func (m *Manager) cancelOpen(ctx context.Context, peer protocol.Peer, req protocol.TerminalCancel) (*protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.attempts[attemptKey{peer: peer.ID(), requestID: req.RequestID}]
	switch {
	case a == nil || a.owner != p.UserID || a.state == attemptCancelled:
		return nil, fault.New(fault.NotFound, "")
	case a.state == attemptCommitted:
		return nil, fault.New(fault.Conflict, "The connection was already established.")
	}
	a.state = attemptCancelled
	a.cancel()
	return nil, nil
}
