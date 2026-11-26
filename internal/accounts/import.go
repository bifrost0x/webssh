package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// ImportTx stores an account taken over from the Python release (entity
// E01) with its legacy id, inside the migration's transaction. The
// username is stored byte for byte; incarnation and history generation
// are the frozen values of migration specification 4.2 (an account
// without creation time has an empty incarnation and the legacy password
// hash as its history generation). The id floor is raised past the id.
func ImportTx(ctx context.Context, tx *store.Tx, a Account) error {
	switch {
	case a.ID <= 0:
		return fmt.Errorf("accounts: import: invalid id %d", a.ID)
	case a.Username == "":
		return fmt.Errorf("accounts: import: account %d has no username", a.ID)
	case a.HistoryGeneration == "":
		return fmt.Errorf("accounts: import: account %d has no history generation", a.ID)
	case a.Managed != ManagedLocal && a.Managed != ManagedLDAP && a.Managed != ManagedGitHub:
		return fmt.Errorf("accounts: import: account %d has manager %q", a.ID, a.Managed)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO accounts_users (id, username, incarnation, history_generation, created_us,
		last_login_us, is_admin, is_locked, auth_generation, mfa_required, managed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Username, a.Incarnation, a.HistoryGeneration, micros(a.CreatedAt), micros(a.LastLogin), a.IsAdmin,
		a.IsLocked, a.AuthGeneration, a.MFARequired, string(a.Managed))
	if err != nil {
		return fmt.Errorf("accounts: import account %d: %w", a.ID, err)
	}
	return (&Service{}).RaiseIDFloorTx(ctx, tx, a.ID)
}

// GetTx reads one account inside a transaction, for the migration's
// verification.
func GetTx(ctx context.Context, tx *store.Tx, id int64) (Account, error) {
	a, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM accounts_users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, errNotFound
	}
	return a, err
}

// IDFloorTx returns the id floor: every new id is larger.
func IDFloorTx(ctx context.Context, tx *store.Tx) (int64, error) {
	var v int64
	if err := tx.QueryRowContext(ctx, `SELECT value FROM accounts_id_floor WHERE singleton = 1`).Scan(&v); err != nil {
		return 0, fmt.Errorf("accounts: read id floor: %w", err)
	}
	return v, nil
}

// ImportQuarantineTx records the directory of a deleted Python account
// (deleted_users/user_<id>_<hex>, entity E33). It is an index only: the
// files stay where they are and are never associated with the account
// that now holds the same id. The id floor is raised past formerID.
func ImportQuarantineTx(ctx context.Context, tx *store.Tx, path string, formerID int64, found time.Time) error {
	if path == "" || formerID <= 0 {
		return fmt.Errorf("accounts: import: invalid quarantine entry %q", path)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO accounts_quarantine (path, former_user_id, found_us) VALUES (?, ?, ?)`,
		path, formerID, found.UnixMicro()); err != nil {
		return fmt.Errorf("accounts: import quarantine %q: %w", path, err)
	}
	return (&Service{}).RaiseIDFloorTx(ctx, tx, formerID)
}

// QuarantineTx lists the recorded directories of deleted accounts with
// their former ids.
func QuarantineTx(ctx context.Context, tx *store.Tx) (map[string]int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT path, former_user_id FROM accounts_quarantine`)
	if err != nil {
		return nil, fmt.Errorf("accounts: read quarantine: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var p string
		var id int64
		if err := rows.Scan(&p, &id); err != nil {
			return nil, fmt.Errorf("accounts: read quarantine: %w", err)
		}
		out[p] = id
	}
	return out, rows.Err()
}

func micros(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMicro()
}
