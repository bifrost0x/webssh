package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Backoff for consecutive rejected one-time codes, as app/mfa_throttle.py.
//
// A TOTP code accepts three of a million values per attempt, so request
// rate limits alone allow a slow online search. Failures are counted per
// account in the database. Sign-in codes and step-up codes have separate
// counters: a password holder cannot block step-up in the owner's
// sessions, and a stolen session cannot block the owner's sign-in. The
// wait grows exponentially to a cap and the count halves for every quiet
// period, so the backoff never becomes a lockout.
const (
	FreeAttempts           = 3
	BackoffBase            = 30 * time.Second
	BackoffMax             = 15 * time.Minute
	QuietPeriod            = 2 * BackoffMax
	PendingDiscardFailures = 5
)

// Scope separates the two failure counters.
type Scope string

// Counter scopes.
const (
	ScopeLogin  Scope = "login"
	ScopeStepUp Scope = "step_up"
)

var errScope = errors.New("auth: unknown one-time code scope")

// Backoff returns the wait after failures consecutive rejections.
func Backoff(failures int) time.Duration {
	if failures < FreeAttempts {
		return 0
	}
	exp := min(failures-FreeAttempts, 16)
	return min(BackoffBase<<exp, BackoffMax)
}

// PendingShouldBeDiscarded reports whether a rejected sign-in code with
// this failure count ends the pending sign-in.
func PendingShouldBeDiscarded(failures int) bool {
	return failures >= PendingDiscardFailures
}

// Throttle keeps the failure counters in the store.
type Throttle struct {
	DB  *store.DB
	Now func() time.Time
}

func (t *Throttle) now() time.Time {
	if t.Now != nil {
		return t.Now().UTC()
	}
	return time.Now().UTC()
}

// Claim reserves one code check for userID and returns the failure count
// including this attempt. The attempt is counted as a failure before the
// code is checked and cleared by Succeeded, so concurrent requests cannot
// pass the backoff together. While the account has to wait, Claim fails
// with fault.RateLimited and the remaining time.
func (t *Throttle) Claim(ctx context.Context, userID int64, scope Scope) (int, error) {
	if scope != ScopeLogin && scope != ScopeStepUp {
		return 0, errScope
	}
	now := t.now()
	var failures int
	err := t.DB.Write(ctx, func(tx *store.Tx) error {
		var stored int
		var last sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT failures, last_failed_at FROM auth_mfa_throttle WHERE user_id = ? AND scope = ?`,
			userID, string(scope)).Scan(&stored, &last)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("auth: read code backoff: %w", err)
		}
		failures = stored
		if last.Valid {
			quiet := max(now.Sub(fromMicros(last.Int64)), 0)
			if periods := int(quiet / QuietPeriod); periods > 0 {
				// The quiet period exceeds the longest wait, so a decayed
				// count never waits for its own backoff.
				failures >>= min(periods, 62)
			} else if wait := Backoff(failures); wait > 0 {
				if ready := fromMicros(last.Int64).Add(wait); ready.After(now) {
					return Throttled(ready.Sub(now))
				}
			}
		}
		failures++
		_, err = tx.ExecContext(ctx, `INSERT INTO auth_mfa_throttle (user_id, scope, failures, last_failed_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (user_id, scope) DO UPDATE SET failures = excluded.failures, last_failed_at = excluded.last_failed_at`,
			userID, string(scope), failures, micros(now))
		if err != nil {
			return fmt.Errorf("auth: store code backoff: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return failures, nil
}

// Throttled is the rate_limited error with the Python wording.
func Throttled(remaining time.Duration) error {
	seconds := max(1, int64(math.Ceil(remaining.Seconds())))
	var message string
	if seconds >= 60 {
		minutes := (seconds + 59) / 60
		message = fmt.Sprintf("Too many attempts. Try again in %d minute%s.", minutes, plural(minutes))
	} else {
		message = fmt.Sprintf("Too many attempts. Try again in %d second%s.", seconds, plural(seconds))
	}
	e := fault.New(fault.RateLimited, message)
	e.RetryAfter = time.Duration(seconds) * time.Second
	return e
}

func plural(n int64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Succeeded clears the counter of scope after an accepted code.
func (t *Throttle) Succeeded(ctx context.Context, userID int64, scope Scope) error {
	if scope != ScopeLogin && scope != ScopeStepUp {
		return errScope
	}
	return t.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_mfa_throttle WHERE user_id = ? AND scope = ?`, userID, string(scope))
		if err != nil {
			return fmt.Errorf("auth: clear code backoff: %w", err)
		}
		return nil
	})
}

// ClearTx clears both counters of userID in the caller's transaction, when
// the owner proved possession another way or the factors were replaced.
func ClearTx(ctx context.Context, tx *store.Tx, userID int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_mfa_throttle WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("auth: clear code backoff: %w", err)
	}
	return nil
}

// ResetAll clears both counters of userID.
func (t *Throttle) ResetAll(ctx context.Context, userID int64) error {
	return t.DB.Write(ctx, func(tx *store.Tx) error { return ClearTx(ctx, tx, userID) })
}

// ImportThrottleTx stores a migrated counter (migration of E01).
func ImportThrottleTx(ctx context.Context, tx *store.Tx, userID int64, scope Scope, failures int, lastFailed time.Time) error {
	if scope != ScopeLogin && scope != ScopeStepUp || failures < 0 {
		return errScope
	}
	if failures == 0 {
		return nil
	}
	var last any
	if !lastFailed.IsZero() {
		last = micros(lastFailed)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO auth_mfa_throttle (user_id, scope, failures, last_failed_at) VALUES (?, ?, ?, ?)`,
		userID, string(scope), failures, last)
	if err != nil {
		return fmt.Errorf("auth: import code backoff: %w", err)
	}
	return nil
}
