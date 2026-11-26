package session

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Subscribe registers fn for every revocation (realtime.Revocations). fn
// runs synchronously in the revoking call and must not block.
func (s *Service) Subscribe(fn func(principal.Revocation)) (cancel func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextID
	s.nextID++
	s.subs[id] = fn
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.subs, id)
	}
}

// Publish delivers revocations committed by a caller's transaction
// (RevokeUserTx). It must run after the commit and before the caller
// reports success.
func (s *Service) Publish(revs []principal.Revocation) {
	s.mu.Lock()
	fns := make([]func(principal.Revocation), 0, len(s.subs))
	for _, fn := range s.subs {
		fns = append(fns, fn)
	}
	s.mu.Unlock()
	for _, rev := range revs {
		for _, fn := range fns {
			fn(rev)
		}
	}
}

// Revoke ends one session. Ending a session that no longer exists is not
// an error.
func (s *Service) Revoke(ctx context.Context, id string, reason principal.Reason) error {
	var revs []principal.Revocation
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		var err error
		revs, err = s.deleteWhere(ctx, tx, reason, `id = ?`, id)
		return err
	})
	if err != nil {
		return storageErr(err)
	}
	s.Publish(revs)
	return nil
}

// RevokeUser ends every session of userID except the session except (""
// for none) and returns how many ended.
func (s *Service) RevokeUser(ctx context.Context, userID int64, reason principal.Reason, except string) (int, error) {
	var revs []principal.Revocation
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		var err error
		revs, err = s.RevokeUserTx(ctx, tx, userID, reason, except)
		return err
	})
	if err != nil {
		return 0, storageErr(err)
	}
	s.Publish(revs)
	return len(revs), nil
}

// RevokeUserTx deletes the sessions inside the caller's transaction and
// returns the revocations the caller passes to Publish after the commit.
func (s *Service) RevokeUserTx(ctx context.Context, tx *store.Tx, userID int64, reason principal.Reason, except string) ([]principal.Revocation, error) {
	return s.deleteWhere(ctx, tx, reason, `user_id = ? AND id <> ?`, userID, except)
}

// RevokeSessionsTx deletes the listed sessions of userID inside the
// caller's transaction.
func (s *Service) RevokeSessionsTx(ctx context.Context, tx *store.Tx, userID int64, ids []string, reason principal.Reason) ([]principal.Revocation, error) {
	var revs []principal.Revocation
	for _, id := range ids {
		r, err := s.deleteWhere(ctx, tx, reason, `user_id = ? AND id = ?`, userID, id)
		if err != nil {
			return nil, err
		}
		revs = append(revs, r...)
	}
	return revs, nil
}

// RevokeAll raises the installation's epoch and ends every session
// (the Go counterpart of rotating session_epoch).
func (s *Service) RevokeAll(ctx context.Context, reason principal.Reason) (int, error) {
	var revs []principal.Revocation
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE session_epoch SET value = ? WHERE singleton = 1`, randomHex(32)); err != nil {
			return fmt.Errorf("session: rotate epoch: %w", err)
		}
		var err error
		revs, err = s.deleteWhere(ctx, tx, reason, `1 = 1`)
		return err
	})
	if err != nil {
		return 0, storageErr(err)
	}
	s.Publish(revs)
	return len(revs), nil
}

// Sweep removes expired sessions and publishes their end. The composition
// root runs it periodically; validation catches expiry on its own.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	var revs []principal.Revocation
	now := s.now().UnixMicro()
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		var err error
		revs, err = s.deleteWhere(ctx, tx, principal.ReasonExpired, `expires_us <= ?`, now)
		return err
	})
	if err != nil {
		return 0, storageErr(err)
	}
	s.Publish(revs)
	return len(revs), nil
}

// deleteWhere deletes sessions and records their end in the revocation
// journal, which other processes on the same database follow.
func (s *Service) deleteWhere(ctx context.Context, tx *store.Tx, reason principal.Reason, where string, args ...any) ([]principal.Revocation, error) {
	revs, err := deleteSessions(ctx, tx, reason, where, args...)
	if err != nil {
		return nil, err
	}
	return revs, s.journal(ctx, tx, revs)
}

func deleteSessions(ctx context.Context, tx *store.Tx, reason principal.Reason, where string, args ...any) ([]principal.Revocation, error) {
	rows, err := tx.QueryContext(ctx, `DELETE FROM session_sessions WHERE `+where+` RETURNING id, user_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("session: delete: %w", err)
	}
	defer rows.Close()
	var revs []principal.Revocation
	for rows.Next() {
		r := principal.Revocation{Reason: reason}
		if err := rows.Scan(&r.SessionID, &r.UserID); err != nil {
			return nil, fmt.Errorf("session: delete: %w", err)
		}
		revs = append(revs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session: delete: %w", err)
	}
	return revs, nil
}

// ClearRecovery lifts the recovery restriction of a session after the
// factor repair (clear_recovery_restriction): the recovery method is
// removed, replacement (a factor kind, may be empty) is added, and with
// mfaOff the assurance drops to Basic. It reports whether the session was
// restricted.
func (s *Service) ClearRecovery(ctx context.Context, id, replacement string, mfaOff bool) (bool, error) {
	var cleared bool
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		var err error
		cleared, err = clearRecoveryTx(ctx, tx, id, replacement, mfaOff)
		return err
	})
	if err != nil {
		return false, storageErr(err)
	}
	return cleared, nil
}

// EndRecovery is ClearRecovery inside the caller's write transaction
// (auth.RecoverySessions): the factor change and the end of the recovery
// restriction commit together.
func (s *Service) EndRecovery(ctx context.Context, tx *store.Tx, sessionID, replacement string, basic bool) error {
	if _, err := clearRecoveryTx(ctx, tx, sessionID, replacement, basic); err != nil {
		return storageErr(err)
	}
	return nil
}

func clearRecoveryTx(ctx context.Context, tx *store.Tx, id, replacement string, mfaOff bool) (bool, error) {
	if replacement != "" && !methodPattern.MatchString(replacement) {
		return false, fault.New(fault.InvalidRequest, "")
	}
	sess, err := scanSession(tx.QueryRowContext(ctx, `SELECT `+selectColumns+` FROM session_sessions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return false, errNotEligible
	}
	if err != nil {
		return false, err
	}
	if !sess.Recovery() {
		return false, nil
	}
	methods := slices.DeleteFunc(slices.Clone(sess.Methods), func(m string) bool { return m == MethodRecovery })
	if replacement != "" && !slices.Contains(methods, replacement) {
		methods = append(methods, replacement)
	}
	if len(methods) == 0 {
		return false, fault.New(fault.Conflict, "")
	}
	assurance := sess.Assurance
	if mfaOff {
		assurance = Basic
	}
	raw, _ := json.Marshal(methods)
	if _, err := tx.ExecContext(ctx, `UPDATE session_sessions SET methods = ?, assurance = ? WHERE id = ?`, string(raw), string(assurance), id); err != nil {
		return false, fmt.Errorf("session: clear recovery: %w", err)
	}
	return true, nil
}
