package accounts

import (
	"context"
	"fmt"
	"regexp"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

// UserData removes every row a deleted account owns outside
// accounts_users and its browser sessions, inside the deletion's write
// transaction, and returns the number of rows removed per table. TablesTx
// lists the tables DeleteUserTx empties, for the retained copy.
type UserData interface {
	TablesTx(ctx context.Context, tx *store.Tx) ([]string, error)
	DeleteUserTx(ctx context.Context, tx *store.Tx, userID int64) (map[string]int64, error)
}

// OwnerColumn is the column that names the owning account. Every store
// keys per-account rows by it; there is no foreign key across owners.
const OwnerColumn = "user_id"

// TableSweep is the UserData of the composition root: it removes the
// account's rows from every table that has an OwnerColumn, except the
// tables in Keep. Because it reads the tables from the database, a store
// added later is covered without a change here (fail closed: a table is
// emptied of the account's rows unless it is named in Keep).
type TableSweep struct {
	// Keep maps a table to the reason it is not swept.
	Keep map[string]string
}

// DefaultKeep are the tables the sweep never touches: the accounts row
// itself (deleted last by Delete), the browser sessions (ended through
// Sessions, which journals each end for other processes) and the
// revocation journal (its rows describe ended sessions, not account data).
var DefaultKeep = map[string]string{
	"accounts_users":      "deleted by the account service after the sweep",
	"session_sessions":    "ended through the session service with a journal entry",
	"session_revocations": "journal of ended sessions that other processes follow",
}

var tableName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// OwnedTablesTx lists the tables with an OwnerColumn, sorted.
func OwnedTablesTx(ctx context.Context, tx *store.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT m.name FROM sqlite_schema AS m, pragma_table_info(m.name) AS c
		WHERE m.type = 'table' AND c.name = ? ORDER BY m.name`, OwnerColumn)
	if err != nil {
		return nil, fmt.Errorf("accounts: list owned tables: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("accounts: list owned tables: %w", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("accounts: list owned tables: %w", err)
	}
	return out, nil
}

// TablesTx implements UserData: the owned tables not in Keep.
func (t TableSweep) TablesTx(ctx context.Context, tx *store.Tx) ([]string, error) {
	tables, err := OwnedTablesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, name := range tables {
		if _, keep := t.Keep[name]; keep {
			continue
		}
		if !tableName.MatchString(name) {
			// Store owners create only lower-case names; anything else is
			// not one of ours and must not stay behind silently.
			return nil, fmt.Errorf("accounts: sweep: unexpected table name %q", name)
		}
		out = append(out, name)
	}
	return out, nil
}

// DeleteUserTx implements UserData.
func (t TableSweep) DeleteUserTx(ctx context.Context, tx *store.Tx, userID int64) (map[string]int64, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("accounts: sweep: invalid user id %d", userID)
	}
	tables, err := t.TablesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, name := range tables {
		// #nosec G202 -- the name comes from sqlite_schema and matches tableName.
		res, err := tx.ExecContext(ctx, `DELETE FROM "`+name+`" WHERE `+OwnerColumn+` = ?`, userID)
		if err != nil {
			return nil, fmt.Errorf("accounts: sweep %s: %w", name, err)
		}
		if n, err := res.RowsAffected(); err == nil && n > 0 {
			out[name] = n
		}
	}
	return out, nil
}

// sortedKeys returns the keys of m in order, for logs.
func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// FactorTables are the tables of second factors and their pending
// ceremonies that an administrator MFA reset empties for the account:
// passkeys and WebAuthn challenges, TOTP authenticators and enrollments,
// recovery codes and the one-time code backoff (admin_reset_user_mfa).
var FactorTables = []string{
	"webauthn_credentials", "webauthn_challenges",
	"totp_authenticators", "totp_enrollments",
	"auth_recovery_codes", "auth_mfa_throttle",
}

// TableReset is the Factors of the composition root: it removes the
// account's rows from exactly the listed tables. A listed table that does
// not exist or has no OwnerColumn fails the reset (fail closed), so a
// renamed factor store cannot be skipped silently.
type TableReset struct {
	Tables []string
}

// ResetTx implements Factors.
func (t TableReset) ResetTx(ctx context.Context, tx *store.Tx, userID int64) error {
	if userID <= 0 || len(t.Tables) == 0 {
		return fmt.Errorf("accounts: factor reset: invalid request for user %d", userID)
	}
	owned, err := OwnedTablesTx(ctx, tx)
	if err != nil {
		return err
	}
	for _, name := range t.Tables {
		if !tableName.MatchString(name) || !slices.Contains(owned, name) {
			return fmt.Errorf("accounts: factor reset: table %q has no %s column", name, OwnerColumn)
		}
		// #nosec G202 -- the name is one of the owned tables read from sqlite_schema.
		if _, err := tx.ExecContext(ctx, `DELETE FROM "`+name+`" WHERE `+OwnerColumn+` = ?`, userID); err != nil {
			return fmt.Errorf("accounts: factor reset %s: %w", name, err)
		}
	}
	return nil
}
