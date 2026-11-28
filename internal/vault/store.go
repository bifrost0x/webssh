package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/naming"
	"github.com/bifrost0x/webssh/internal/store"
)

// Key states (column state).
const (
	stateUsable      = "usable"
	stateUnsupported = "unsupported"
)

// keyRow is one stored key.
type keyRow struct {
	ID          string
	UserID      int64
	Seq         int64
	Name        string
	KeyType     string
	PublicKey   string
	Fingerprint string
	Sealed      []byte
	UploadedAt  string
	State       string
}

// aad binds a sealed key to its owner and row.
func aad(userID int64, id string) keyring.AAD {
	return keyring.AAD{Table: "vault_ssh_keys", Column: "private_key", Row: strconv.FormatInt(userID, 10) + ":" + id}
}

const keyColumns = `id, user_id, seq, name, key_type, public_key, fingerprint_sha256, private_key, uploaded_at, state`

func scanKey(scan func(...any) error) (keyRow, error) {
	var r keyRow
	err := scan(&r.ID, &r.UserID, &r.Seq, &r.Name, &r.KeyType, &r.PublicKey, &r.Fingerprint, &r.Sealed, &r.UploadedAt, &r.State)
	return r, err
}

func listRows(ctx context.Context, tx *store.Tx, userID int64) ([]keyRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+keyColumns+` FROM vault_ssh_keys WHERE user_id = ? ORDER BY seq`, userID)
	if err != nil {
		return nil, fmt.Errorf("vault: list keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []keyRow
	for rows.Next() {
		r, err := scanKey(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("vault: list keys: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vault: list keys: %w", err)
	}
	return out, nil
}

// getRow returns the user's key; found is false for an unknown ID and for
// another user's key.
func getRow(ctx context.Context, tx *store.Tx, userID int64, id string) (r keyRow, found bool, err error) {
	r, err = scanKey(tx.QueryRowContext(ctx, `SELECT `+keyColumns+` FROM vault_ssh_keys WHERE user_id = ? AND id = ?`, userID, id).Scan)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return keyRow{}, false, nil
	case err != nil:
		return keyRow{}, false, fmt.Errorf("vault: read key: %w", err)
	}
	return r, true, nil
}

// usage returns the number of the user's keys and their sealed bytes.
func usage(ctx context.Context, tx *store.Tx, userID int64) (count, size int64, err error) {
	err = tx.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(length(private_key)), 0) FROM vault_ssh_keys WHERE user_id = ?`, userID).Scan(&count, &size)
	if err != nil {
		return 0, 0, fmt.Errorf("vault: key usage: %w", err)
	}
	return count, size, nil
}

func insertRow(ctx context.Context, tx *store.Tx, r keyRow) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO vault_ssh_keys (`+keyColumns+`)
VALUES (?, ?, (SELECT coalesce(max(seq), 0) + 1 FROM vault_ssh_keys WHERE user_id = ?), ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.UserID, r.UserID, r.Name, r.KeyType, r.PublicKey, r.Fingerprint, r.Sealed, r.UploadedAt, r.State)
	if err != nil {
		return fmt.Errorf("vault: insert key: %w", err)
	}
	return nil
}

func renameRow(ctx context.Context, tx *store.Tx, userID int64, id, name string) error {
	return execOne(ctx, tx, `UPDATE vault_ssh_keys SET name = ? WHERE user_id = ? AND id = ?`, name, userID, id)
}

func replaceRow(ctx context.Context, tx *store.Tx, r keyRow) error {
	return execOne(ctx, tx, `UPDATE vault_ssh_keys SET key_type = ?, public_key = ?, fingerprint_sha256 = ?, private_key = ?, state = ?
WHERE user_id = ? AND id = ?`, r.KeyType, r.PublicKey, r.Fingerprint, r.Sealed, r.State, r.UserID, r.ID)
}

func deleteRow(ctx context.Context, tx *store.Tx, userID int64, id string) error {
	return execOne(ctx, tx, `DELETE FROM vault_ssh_keys WHERE user_id = ? AND id = ?`, userID, id)
}

// execOne runs a statement that must change exactly one row; no row is
// errNotFound.
func execOne(ctx context.Context, tx *store.Tx, query string, args ...any) error {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("vault: write key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("vault: write key: %w", err)
	}
	if n != 1 {
		return errNotFound
	}
	return nil
}

var errKeyName = fault.New(fault.DuplicateName, "A key with this name already exists")

// checkKeyName refuses a key name another key of the user already has
// (internal/naming). own is the key being renamed, "" for a new one; a key
// that keeps its own name is never refused, so duplicates migrated from
// 3.3 stay usable.
func checkKeyName(ctx context.Context, tx *store.Tx, userID int64, own, name string) error {
	rows, err := listRows(ctx, tx, userID)
	if err != nil {
		return err
	}
	names := make([]string, len(rows))
	var mine []int
	for i, r := range rows {
		names[i] = r.Name
		if r.ID == own {
			mine = append(mine, i)
		}
	}
	if naming.Taken(names, mine, name) {
		return errKeyName
	}
	return nil
}
