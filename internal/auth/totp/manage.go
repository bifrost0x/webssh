package totp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Authenticator is an active authenticator as the Security page lists it.
type Authenticator struct {
	ID         int64
	Label      string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if never used
}

var (
	errNotFound   = fault.New(fault.NotFound, "Authenticator not found")
	errLastFactor = fault.New(fault.LastFactorRequired, "Add a replacement factor or disable MFA first")
)

// Count implements auth.DurableFactor: the active authenticators of userID.
func (s *Service) Count(ctx context.Context, tx *store.Tx, userID int64) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM totp_authenticators WHERE user_id = ? AND active = 1`, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("totp: count authenticators: %w", err)
	}
	return n, nil
}

// RemoveAll implements auth.FactorRemover.
func (s *Service) RemoveAll(ctx context.Context, tx *store.Tx, userID int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_authenticators WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("totp: remove authenticators: %w", err)
	}
	return nil
}

// List returns the active authenticators of userID in id order.
func (s *Service) List(ctx context.Context, userID int64) ([]Authenticator, error) {
	var out []Authenticator
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, label, created_at, last_used_at FROM totp_authenticators
			WHERE user_id = ? AND active = 1 ORDER BY id`, userID)
		if err != nil {
			return fmt.Errorf("totp: list authenticators: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a Authenticator
			var created int64
			var used sql.NullInt64
			if err := rows.Scan(&a.ID, &a.Label, &created, &used); err != nil {
				return fmt.Errorf("totp: list authenticators: %w", err)
			}
			a.CreatedAt = time.UnixMicro(created).UTC()
			if used.Valid {
				a.LastUsedAt = time.UnixMicro(used.Int64).UTC()
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// Owned reports whether id is an authenticator of userID.
func (s *Service) Owned(ctx context.Context, userID, id int64) (bool, error) {
	var owner int64
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT user_id FROM totp_authenticators WHERE id = ?`, id).Scan(&owner)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("totp: read authenticator: %w", err)
	}
	return owner == userID, nil
}

// Delete removes the principal's authenticator id. With MFA on, the last
// usable factor cannot be removed. It returns whether MFA is still on. The
// caller has consumed the totp.delete grant for id.
func (s *Service) Delete(ctx context.Context, p principal.Principal, id int64) (mfaOn bool, err error) {
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		var owner int64
		var active bool
		err := tx.QueryRowContext(ctx, `SELECT user_id, active FROM totp_authenticators WHERE id = ?`, id).Scan(&owner, &active)
		if errors.Is(err, sql.ErrNoRows) || err == nil && owner != p.UserID {
			return errNotFound
		}
		if err != nil {
			return fmt.Errorf("totp: read authenticator: %w", err)
		}
		if mfaOn, err = s.MFA.Accounts.MFARequired(ctx, tx, p.UserID); err != nil {
			return err
		}
		counts, err := s.MFA.CountsTx(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		remaining := counts.Total
		if active && counts.TOTP > 0 {
			remaining--
		}
		if mfaOn && remaining == 0 {
			return errLastFactor
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM totp_authenticators WHERE id = ?`, id)
		return err
	})
	return mfaOn, err
}

// Imported is a TOTP authenticator taken over by the migration (E08).
type Imported struct {
	ID, UserID       int64
	Label            string
	Base32           string // the secret as the user's app holds it
	Active           bool
	LastAcceptedStep sql.NullInt64
	CreatedAt        time.Time
	ActivatedAt      time.Time // zero if unknown
	LastUsedAt       time.Time // zero if never used
}

// ImportTx stores a migrated authenticator with its legacy id, sealing the
// secret with the keyring. The replay state is kept.
func (s *Service) ImportTx(ctx context.Context, tx *store.Tx, a Imported) error {
	if _, err := otp.DecodeSecret(a.Base32); err != nil {
		return fmt.Errorf("totp: authenticator %d: %w", a.ID, err)
	}
	sealed, err := s.seal("totp_authenticators", a.ID, a.UserID, a.Base32)
	if err != nil {
		return err
	}
	var activated, used any
	if !a.ActivatedAt.IsZero() {
		activated = a.ActivatedAt.UnixMicro()
	}
	if !a.LastUsedAt.IsZero() {
		used = a.LastUsedAt.UnixMicro()
	}
	var last any
	if a.LastAcceptedStep.Valid {
		last = a.LastAcceptedStep.Int64
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO totp_authenticators (id, user_id, label, sealed_secret, active, last_accepted_step, created_at, activated_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, a.ID, a.UserID, a.Label, sealed, a.Active, last, a.CreatedAt.UnixMicro(), activated, used)
	if err != nil {
		return fmt.Errorf("totp: import authenticator %d: %w", a.ID, err)
	}
	return nil
}

// Enrolled reports whether userID has an active authenticator.
func (s *Service) Enrolled(ctx context.Context, userID int64) (bool, error) {
	var n int
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		n, err = s.Count(ctx, tx, userID)
		return err
	})
	return n > 0, err
}

// OwnsTarget is the step-up target check of totp.delete: the target is the
// id of one of p's authenticators.
func (s *Service) OwnsTarget(ctx context.Context, p principal.Principal, target string) error {
	id, err := strconv.ParseInt(target, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != target {
		return errNotFound
	}
	owned, err := s.Owned(ctx, p.UserID, id)
	if err != nil {
		return err
	}
	if !owned {
		return errNotFound
	}
	return nil
}
