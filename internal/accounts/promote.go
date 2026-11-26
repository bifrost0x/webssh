package accounts

import (
	"context"
	"database/sql"
	"errors"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Promote grants administrator rights to an existing account, the
// promotion of `webssh create-admin` (app/cli.py create_admin). It applies
// CheckPromote inside the write transaction and reports whether the
// account was not an administrator before. The caller audits the outcome.
func (s *Service) Promote(ctx context.Context, id int64) (changed bool, err error) {
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		acc, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM accounts_users WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		if err := CheckPromote(acc); err != nil {
			return err
		}
		if acc.IsAdmin {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE accounts_users SET is_admin = 1 WHERE id = ?`, id); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		if _, ok := fault.From(err); ok {
			return false, err
		}
		return false, fault.Wrap(fault.StorageError, err, "")
	}
	return changed, nil
}
