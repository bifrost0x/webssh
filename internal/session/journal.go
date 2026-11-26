package session

import (
	"context"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// journalRetention bounds how long ended sessions stay in the revocation
// journal. A follower polls every second or two; the retention only has to
// outlast a stalled poll.
const journalRetention = 10 * time.Minute

// journal records revocations committed by this service in the same
// transaction, so that another process on the same database (an
// administrator command beside the running server, or the server beside a
// command) learns of them, and prunes old entries.
func (s *Service) journal(ctx context.Context, tx *store.Tx, revs []principal.Revocation) error {
	if len(revs) == 0 {
		return nil
	}
	now := time.Now().UnixMicro()
	for _, r := range revs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO session_revocations (session_id, user_id, reason, origin, at_us) VALUES (?, ?, ?, ?, ?)`,
			r.SessionID, r.UserID, string(r.Reason), s.origin, now); err != nil {
			return fmt.Errorf("session: journal revocation: %w", err)
		}
	}
	// The newest entry is never pruned: seq is the rowid, and SQLite gives
	// a new row max(rowid)+1, so keeping it keeps seq increasing.
	if _, err := tx.ExecContext(ctx, `DELETE FROM session_revocations WHERE at_us < ? AND seq < (SELECT max(seq) FROM session_revocations)`,
		now-journalRetention.Microseconds()); err != nil {
		return fmt.Errorf("session: prune revocation journal: %w", err)
	}
	return nil
}

// FollowRevocations publishes the revocations that other processes
// committed since the last call, with the same effect as a revocation in
// this process (connections close, terminals end by the reason's rules).
// The first call only notes the current position. The composition root
// calls it periodically; it returns how many it published.
func (s *Service) FollowRevocations(ctx context.Context) (int, error) {
	s.watch.Lock()
	defer s.watch.Unlock()
	var revs []principal.Revocation
	last := s.watch.seq
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		if !s.watch.started {
			return tx.QueryRowContext(ctx, `SELECT coalesce(max(seq), 0) FROM session_revocations`).Scan(&last)
		}
		rows, err := tx.QueryContext(ctx, `SELECT seq, session_id, user_id, reason, origin FROM session_revocations WHERE seq > ? ORDER BY seq`, last)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r principal.Revocation
			var reason, origin string
			if err := rows.Scan(&last, &r.SessionID, &r.UserID, &reason, &origin); err != nil {
				return err
			}
			if origin != s.origin {
				r.Reason = principal.Reason(reason)
				revs = append(revs, r)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return 0, storageErr(err)
	}
	s.watch.seq, s.watch.started = last, true
	s.Publish(revs)
	return len(revs), nil
}
