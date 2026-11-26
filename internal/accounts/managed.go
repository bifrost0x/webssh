package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// Accounts of the external providers (docs/architecture/m2-contracts.md,
// "Managed accounts"). LDAP calls them through cmd/webssh.

// SetManagerTx records who manages the account ("" makes it local again)
// and raises its auth generation, which ends every credential issued
// before (link and unlink of an LDAP identity).
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

// RaiseGenerationTx raises the account's auth generation, which ends every
// session, pending sign-in and step-up grant issued before.
func (s *Service) RaiseGenerationTx(ctx context.Context, tx *store.Tx, id int64) error {
	res, err := tx.ExecContext(ctx, `UPDATE accounts_users SET auth_generation = auth_generation + 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("accounts: raise generation: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
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
