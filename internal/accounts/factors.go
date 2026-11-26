package accounts

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Factors removes every second factor of an account inside the caller's
// write transaction: passkeys and their pending ceremonies, TOTP
// authenticators and enrollments, recovery codes and the code backoff
// (provided by cmd/webssh over internal/auth/webauthn, internal/auth/totp
// and internal/auth).
type Factors interface {
	ResetTx(ctx context.Context, tx *store.Tx, userID int64) error
}

// RecoveryCodes replaces the recovery codes of an account inside the
// caller's write transaction and returns the new codes (provided by
// internal/auth).
type RecoveryCodes interface {
	ReplaceTx(ctx context.Context, tx *store.Tx, userID int64, count int) ([]string, error)
}

// RecoveryCodeCount is the number of codes an administrator reset issues,
// as generate_codes of the Python release.
const RecoveryCodeCount = 10

// ErrTargetConfirmation refuses a reset whose confirmation does not name
// the target account exactly.
var ErrTargetConfirmation = fault.New(fault.InvalidValue, "Target confirmation does not match")

// ResetMFA removes every second factor of targetID, turns MFA off, raises
// the auth_generation and ends every session and live resource of the
// account (admin_reset_user_mfa). confirm must equal the account name
// byte for byte. The administrator may reset the own account; the own
// session then ends as well.
func (s *Service) ResetMFA(ctx context.Context, actor principal.Principal, targetID int64, confirm string) error {
	if s.Factors == nil {
		return fault.New(fault.Unavailable, "")
	}
	var acc Account
	var revs []principal.Revocation
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		if acc, err = getTx(ctx, tx, targetID); err != nil {
			return err
		}
		if confirm != acc.Username {
			return ErrTargetConfirmation
		}
		if err := s.Factors.ResetTx(ctx, tx, acc.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE accounts_users SET mfa_required = 0 WHERE id = ?`, acc.ID); err != nil {
			return fmt.Errorf("accounts: reset mfa: %w", err)
		}
		revs, err = s.invalidateTx(ctx, tx, acc.ID, principal.ReasonFactorChanged)
		return err
	})
	if err != nil {
		return storage(err)
	}
	s.announce(acc.ID, principal.ReasonFactorChanged, revs)
	s.logger().Warn("Admin reset user MFA", "admin", actor.Username, "user", acc.Username)
	s.warn("ADMIN_USER_MFA_RESET", "admin", actor.Username, "user", acc.Username)
	return nil
}

// ReplaceRecovery issues new recovery codes for targetID and returns them
// once (admin_recovery). confirm must equal the account name. Sessions
// are not affected, as in the Python release.
func (s *Service) ReplaceRecovery(ctx context.Context, actor principal.Principal, targetID int64, confirm string) ([]string, error) {
	if s.Recovery == nil {
		return nil, fault.New(fault.Unavailable, "")
	}
	var acc Account
	var codes []string
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		if acc, err = getTx(ctx, tx, targetID); err != nil {
			return err
		}
		if confirm != acc.Username {
			return ErrTargetConfirmation
		}
		codes, err = s.Recovery.ReplaceTx(ctx, tx, acc.ID, RecoveryCodeCount)
		return err
	})
	if err != nil {
		return nil, storage(err)
	}
	s.warn("ADMIN_RECOVERY_CODES_REGENERATED", "admin", actor.Username, "user", acc.Username)
	return codes, nil
}
