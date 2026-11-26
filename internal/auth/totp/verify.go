package totp

import (
	"context"
	"database/sql"
	"encoding/base32"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

func encodeSecret(key []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
}

// VerifyCode accepts code for one of userID's active authenticators once.
// The first authenticator (by id) whose code matches at a step after its
// last accepted step wins and records the step; the check and the update
// are one serialized write, so concurrent requests cannot use a code
// twice. A secret that cannot be opened is skipped and logged.
func (s *Service) VerifyCode(ctx context.Context, userID int64, code string) (bool, error) {
	now := s.now()
	matched := false
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, sealed_secret, last_accepted_step FROM totp_authenticators
			WHERE user_id = ? AND active = 1 ORDER BY id`, userID)
		if err != nil {
			return fmt.Errorf("totp: read authenticators: %w", err)
		}
		type candidate struct {
			id     int64
			sealed []byte
			last   sql.NullInt64
		}
		var all []candidate
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.id, &c.sealed, &c.last); err != nil {
				return errors.Join(fmt.Errorf("totp: read authenticators: %w", err), rows.Close())
			}
			all = append(all, c)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("totp: read authenticators: %w", err)
		}
		for _, c := range all {
			key, err := s.open("totp_authenticators", c.id, userID, c.sealed)
			if err != nil {
				s.logger().WarnContext(ctx, "TOTP secret could not be opened", "user_id", userID, "authenticator_id", c.id)
				continue
			}
			step, ok := acceptedStep(key, code, now)
			if !ok || c.last.Valid && int64(step) <= c.last.Int64 { // #nosec G115 -- a time step fits in int64
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE totp_authenticators SET last_accepted_step = ?, last_used_at = ? WHERE id = ?`,
				int64(step), now.UnixMicro(), c.id); err != nil { // #nosec G115 -- a time step fits in int64
				return fmt.Errorf("totp: record accepted step: %w", err)
			}
			matched = true
			return nil
		}
		return nil
	})
	return matched, err
}

// Rejected is the cause of a rejected code: the consecutive failures of the
// account so far, which decide whether a pending sign-in ends.
type Rejected struct{ Failures int }

func (r *Rejected) Error() string {
	return fmt.Sprintf("totp: code rejected (%d consecutive failures)", r.Failures)
}

// Failures returns the failure count of a rejected code, or 0.
func Failures(err error) int {
	if r, ok := errors.AsType[*Rejected](err); ok {
		return r.Failures
	}
	return 0
}

// CheckCode checks code under the backoff of scope: it claims an attempt,
// verifies, and clears the counter on success. It fails with
// fault.RateLimited while the account waits and with fault.AuthFailed
// (cause *Rejected) for a wrong code.
func (s *Service) CheckCode(ctx context.Context, userID int64, code string, scope auth.Scope) error {
	failures, err := s.Throttle.Claim(ctx, userID, scope)
	if err != nil {
		return err
	}
	ok, err := s.VerifyCode(ctx, userID, code)
	if err != nil {
		return err
	}
	if !ok {
		return fault.Wrap(fault.AuthFailed, &Rejected{Failures: failures}, "TOTP code is invalid")
	}
	return s.Throttle.Succeeded(ctx, userID, scope)
}

// Factor is the TOTP sign-in factor of the auth registry.
type Factor struct{ Service *Service }

// Kind implements auth.Factor.
func (Factor) Kind() string { return "totp" }

// Enrolled implements auth.Factor.
func (f Factor) Enrolled(ctx context.Context, userID int64) (bool, error) {
	return f.Service.Enrolled(ctx, userID)
}

// Verify implements auth.Factor for a sign-in: response is {"code": "…"}.
func (f Factor) Verify(ctx context.Context, userID int64, response jsontext.Value) error {
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(response, &body) // a malformed response is a wrong code
	return f.Service.CheckCode(ctx, userID, body.Code, auth.ScopeLogin)
}
