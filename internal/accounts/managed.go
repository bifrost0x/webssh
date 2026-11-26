package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// Accounts of the external providers (docs/architecture/m2-contracts.md,
// "Managed accounts"). The provider packages call these inside their own
// transaction, after the caller consumed the step-up grant; ProvisionTx
// lives in provision.go.

// GetTx returns an account by id inside the caller's transaction.
func (s *Service) GetTx(ctx context.Context, tx *store.Tx, id int64) (Account, error) {
	a, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM accounts_users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, errNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("accounts: read: %w", err)
	}
	return a, nil
}

// SetManagerTx records who manages the account ("" makes it local again)
// and raises its auth generation, which ends every credential issued
// before (an existing account linked to an LDAP identity).
func (s *Service) SetManagerTx(ctx context.Context, tx *store.Tx, id int64, manager Manager) error {
	if manager != ManagedLocal && manager != ManagedLDAP && manager != ManagedGitHub {
		return fmt.Errorf("accounts: manager %q", manager)
	}
	res, err := tx.ExecContext(ctx, `UPDATE accounts_users SET managed_by = ?, auth_generation = auth_generation + 1 WHERE id = ?`,
		string(manager), id)
	if err != nil {
		return fmt.Errorf("accounts: set manager: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// ReleaseTx makes a managed account local again when its provider
// identity is removed. A non-empty passwordHash becomes its local password
// (LDAP: the administrator sets one); with an empty one the account keeps
// no password and signs in with a passkey (GitHub: unlinking requires
// one). The auth generation is left to the caller: LDAP raises it with
// RaiseGenerationTx, GitHub through the session renewal.
func (s *Service) ReleaseTx(ctx context.Context, tx *store.Tx, userID int64, passwordHash string) error {
	res, err := tx.ExecContext(ctx, `UPDATE accounts_users SET managed_by = '' WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("accounts: release: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	if passwordHash == "" {
		return nil
	}
	return s.Credentials.StoreTx(ctx, tx, userID, passwordHash)
}

// RaiseGenerationTx raises auth_generation, which ends every credential
// issued under the old one (sessions, pending sign-ins, step-up grants),
// and returns the new generation (invalidate_user_authentication).
func (s *Service) RaiseGenerationTx(ctx context.Context, tx *store.Tx, userID int64) (int64, error) {
	var gen int64
	err := tx.QueryRowContext(ctx, `UPDATE accounts_users SET auth_generation = auth_generation + 1
		WHERE id = ? RETURNING auth_generation`, userID).Scan(&gen)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("accounts: raise generation: %w", err)
	}
	return gen, nil
}

// BreakGlassAdminTx reports whether an unlocked administrator exists that
// no directory manages; LDAP auto-provisioning requires one.
func (s *Service) BreakGlassAdminTx(ctx context.Context, tx *store.Tx) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM accounts_users WHERE is_admin = 1 AND is_locked = 0 AND managed_by <> 'ldap' LIMIT 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("accounts: break-glass administrator: %w", err)
	}
	return true, nil
}
