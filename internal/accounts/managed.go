package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Accounts of the external providers (docs/architecture/m2-contracts.md,
// "Managed accounts"). LDAP calls them through cmd/webssh.

var errNameConflict = fault.New(fault.Conflict, "Username already exists")

// ProvisionTx creates a non-admin account managed by manager ("ldap" or
// "github") without a local password, for a verified external identity.
// A name equal to an existing one after case folding is fault.Conflict;
// the name rules of new local accounts do not apply, the provider checks
// its own (an LDAP name of up to 80 characters).
func (s *Service) ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (int64, error) {
	if manager != string(ManagedLDAP) && manager != string(ManagedGitHub) {
		return 0, fmt.Errorf("accounts: provision: manager %q", manager)
	}
	if username == "" {
		return 0, fault.New(fault.InvalidValue, "")
	}
	_, names, err := existing(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("accounts: provision: %w", err)
	}
	folded := FoldName(username)
	for _, n := range names {
		if FoldName(n) == folded {
			return 0, errNameConflict
		}
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT max((SELECT coalesce(max(id), 0) FROM accounts_users),
		(SELECT value FROM accounts_id_floor WHERE singleton = 1)) + 1`).Scan(&id); err != nil {
		return 0, fmt.Errorf("accounts: next id: %w", err)
	}
	now := s.now()
	inc := pyISO(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO accounts_users (id, username, incarnation, history_generation, created_us,
		is_admin, managed_by) VALUES (?, ?, ?, ?, ?, 0, ?)`, id, username, inc, inc, now.Truncate(time.Microsecond).UnixMicro(), manager); err != nil {
		return 0, fmt.Errorf("accounts: provision: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts_id_floor SET value = ? WHERE singleton = 1`, id); err != nil {
		return 0, fmt.Errorf("accounts: raise id floor: %w", err)
	}
	return id, nil
}

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
