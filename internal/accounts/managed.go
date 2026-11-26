package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Accounts of external providers (docs/architecture/m2-contracts.md,
// "Managed accounts"). The provider packages call these inside their own
// transaction, after the caller consumed the step-up grant.

var errProvisionName = fault.New(fault.Conflict, "Username already exists")

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

// ProvisionTx creates an account for an external provider: never an
// administrator, managed by manager ("ldap" or "github") and without a
// local password. The name follows the rules for new accounts and may be
// one ADMIN_USERS lists: the start-up rule never promotes a managed
// account. A name that is taken (ignoring case) is fault.Conflict, an
// invalid one fault.InvalidValue; the provider then tries another name.
func (s *Service) ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (int64, error) {
	m := Manager(manager)
	if m != ManagedLDAP && m != ManagedGitHub {
		return 0, fmt.Errorf("accounts: %q does not manage accounts", manager)
	}
	if msg := validateNewName(username); msg != "" {
		return 0, invalid(msg)
	}
	_, names, err := existing(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("accounts: read names: %w", err)
	}
	folded := FoldName(username)
	for _, n := range names {
		if FoldName(n) == folded {
			return 0, errProvisionName
		}
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT max((SELECT coalesce(max(id), 0) FROM accounts_users),
		(SELECT value FROM accounts_id_floor WHERE singleton = 1)) + 1`).Scan(&id); err != nil {
		return 0, fmt.Errorf("accounts: next id: %w", err)
	}
	now := s.now()
	inc := pyISO(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO accounts_users (id, username, incarnation, history_generation, created_us, is_admin, managed_by)
		VALUES (?, ?, ?, ?, ?, 0, ?)`, id, username, inc, inc, now.UnixMicro(), string(m)); err != nil {
		return 0, fmt.Errorf("accounts: insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts_id_floor SET value = ? WHERE singleton = 1`, id); err != nil {
		return 0, fmt.Errorf("accounts: raise id floor: %w", err)
	}
	return id, nil
}

// ReleaseTx makes a managed account local again when its provider
// identity is removed. A non-empty passwordHash becomes its local password
// (LDAP: the administrator sets one); with an empty one the account keeps
// no password and signs in with a passkey (GitHub: unlinking requires
// one).
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
