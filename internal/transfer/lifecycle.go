package transfer

import (
	"cmp"
	"context"
	"slices"

	"github.com/bifrost0x/webssh/internal/principal"
)

// consume redeems a token for p. It answers nil for an unknown, used,
// expired or foreign token; a token of the right owner on the wrong route
// is used up and fails (misdirected). The returned transfer is running,
// with a context that ends with parent, a cancel or a revocation.
func (m *Manager) consume(parent context.Context, token string, p principal.Principal, dir Direction, archive bool) (*record, context.Context) {
	if !ValidToken(token) {
		return nil, nil
	}
	m.mu.Lock()
	r, ok := m.tokens[tokenKey(token)]
	if !ok || m.closed || r.state != Pending || r.owner != (principalKey{p.UserID, p.SessionID}) {
		m.mu.Unlock()
		return nil, nil
	}
	delete(m.tokens, r.token)
	r.token = [32]byte{}
	r.expiry.Stop()
	if r.direction != dir || r.archive != archive {
		m.mu.Unlock()
		m.finish(r, Failed, nil, false)
		return nil, nil
	}
	ctx, cancel := context.WithCancelCause(parent)
	r.state, r.cancel = Running, cancel
	m.work.Add(1)
	m.mu.Unlock()
	return r, ctx
}

// end moves a running HTTP transfer to its final state and frees the
// slot of the shutdown wait.
func (m *Manager) end(r *record, state State, f *Failure) {
	m.finish(r, state, f, true)
	r.cancel(nil)
	m.work.Done()
}

// cancelLocked cancels r: a pending transfer ends at once (returned in
// ended), a running one is told to stop with cause.
func cancelLocked(r *record, cause error) (State, bool) {
	switch r.state {
	case Pending:
		return Cancelled, true
	case Running:
		r.state = Cancelling
		r.cancel(cause)
		return Cancelling, false
	}
	return r.state, false
}

// CancelFor cancels a transfer of p's user (cancel_transfer). It answers
// the state: cancelled for a pending one, cancelling for a running one,
// the final state of a recent one or CancelUnavailable.
func (m *Manager) CancelFor(userID int64, id string) State {
	m.mu.Lock()
	r, ok := m.records[id]
	if !ok || r.owner.userID != userID {
		t, known := m.terminal[id]
		m.mu.Unlock()
		if known && t.userID == userID && m.o.Now().Before(t.until) {
			return t.state
		}
		return CancelUnavailable
	}
	state, ended := cancelLocked(r, errCancelled)
	m.mu.Unlock()
	if ended {
		m.finish(r, Cancelled, nil, true)
	}
	return state
}

// cancelWhere cancels the matching transfers that are pending or running.
func (m *Manager) cancelWhere(cause error, match func(*record) bool) int {
	var ended []*record
	n := 0
	m.mu.Lock()
	for _, r := range m.records {
		if r.state == Cancelling || !match(r) {
			continue
		}
		if _, now := cancelLocked(r, cause); now {
			ended = append(ended, r)
		}
		n++
	}
	m.mu.Unlock()
	for _, r := range ended {
		m.finish(r, Cancelled, nil, true)
	}
	return n
}

// PeerOpened notes a realtime connection of the user.
func (m *Manager) PeerOpened(userID int64, peer uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.peers[userID] == nil {
		m.peers[userID] = map[uint64]bool{}
	}
	m.peers[userID][peer] = true
}

// PeerClosed cancels what the closed connection prepared and its
// host-to-host copies, and everything pending of the user when it was the
// last connection. Running HTTP transfers belong to their request and go
// on (a reconnect of the realtime connection keeps them), as in Python.
func (m *Manager) PeerClosed(userID int64, peer uint64) {
	m.mu.Lock()
	set := m.peers[userID]
	delete(set, peer)
	last := len(set) == 0
	if last {
		delete(m.peers, userID)
	}
	m.mu.Unlock()
	m.cancelWhere(errCancelled, func(r *record) bool {
		if r.owner.userID != userID || r.http() && r.state == Running {
			return false
		}
		return last || r.peer == peer
	})
}

// Revoke cancels every transfer of a revoked session, or of the user for
// an account-wide revocation, running HTTP transfers included (K6).
func (m *Manager) Revoke(rev principal.Revocation) {
	m.cancelWhere(errRevoked, func(r *record) bool {
		return r.owner.userID == rev.UserID && (rev.SessionID == "" || r.owner.session == rev.SessionID)
	})
}

// Shutdown refuses new transfers, cancels all and waits until running
// ones stopped or ctx ends.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.cancelWhere(errCancelled, func(*record) bool { return true })
	m.stop()
	done := make(chan struct{})
	go func() { m.work.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Active lists up to limit live transfers for the admin page, oldest
// first, and how many there are: no tokens, no paths.
func (m *Manager) Active(limit int) ([]Active, int) {
	m.mu.Lock()
	all := make([]Active, 0, len(m.records))
	for _, r := range m.records {
		all = append(all, Active{ID: r.id, UserID: r.owner.userID, Direction: r.direction, State: r.state, Started: r.started})
	}
	m.mu.Unlock()
	slices.SortFunc(all, func(a, b Active) int { return cmp.Or(a.Started.Compare(b.Started), cmp.Compare(a.ID, b.ID)) })
	return all[:min(max(limit, 0), len(all))], len(all)
}

// Cancel cancels a transfer for the admin page: the owner is looked up
// here, then it is an ordinary cancel.
func (m *Manager) Cancel(_ context.Context, transferID string) (State, error) {
	m.mu.Lock()
	r, ok := m.records[transferID]
	m.mu.Unlock()
	if !ok {
		return CancelUnavailable, nil
	}
	return m.CancelFor(r.owner.userID, transferID), nil
}
