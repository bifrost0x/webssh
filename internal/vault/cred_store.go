package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// credRow is one saved password; secret is sealed.
type credRow struct {
	ID, Name, Username, Version, UpdatedAt string
	Secret                                 []byte
}

// credDoc is a user's saved passwords as one document, as credentials.json
// was: every mutation loads it, changes it and writes it back inside one
// transaction, so the limits and references hold for the whole document.
type credDoc struct {
	creds   []credRow
	assigns []Assignment
	imports []string
}

// MaxImports bounds the remembered legacy vault imports (credentials.json).
const MaxImports = 100

func credentialAAD(userID int64, id string) keyring.AAD {
	return keyring.AAD{Table: "vault_credentials", Column: "secret", Row: strconv.FormatInt(userID, 10) + ":" + id}
}

func (d *credDoc) record(id string) (*credRow, bool) {
	i := slices.IndexFunc(d.creds, func(c credRow) bool { return c.ID == id })
	if i < 0 {
		return nil, false
	}
	return &d.creds[i], true
}

func (d *credDoc) assignment(resourceID string) (*Assignment, bool) {
	i := slices.IndexFunc(d.assigns, func(a Assignment) bool { return a.ResourceID == resourceID })
	if i < 0 {
		return nil, false
	}
	return &d.assigns[i], true
}

// assign sets the assignment of a resource; an existing one keeps its
// position, as in a Python dict.
func (d *credDoc) assign(a Assignment) {
	if old, ok := d.assignment(a.ResourceID); ok {
		*old = a
		return
	}
	d.assigns = append(d.assigns, a)
}

func (d *credDoc) unassign(resourceID string) {
	d.assigns = slices.DeleteFunc(d.assigns, func(a Assignment) bool { return a.ResourceID == resourceID })
}

func (d *credDoc) uses(credentialID string) []string {
	var out []string
	for _, a := range d.assigns {
		if a.CredentialID == credentialID {
			out = append(out, a.ResourceID)
		}
	}
	return out
}

// valid applies the limits of credential_store.py _valid after a change.
func (d *credDoc) valid() bool {
	if len(d.creds) > MaxCredentials || len(d.assigns) > MaxAssignments || len(d.imports) > MaxImports {
		return false
	}
	for _, a := range d.assigns {
		if _, ok := d.record(a.CredentialID); !ok {
			return false
		}
	}
	return true
}

func loadDoc(ctx context.Context, tx *store.Tx, userID int64) (*credDoc, error) {
	d := &credDoc{}
	rows, err := tx.QueryContext(ctx, `SELECT id, name, username, version, updated_at, secret FROM vault_credentials WHERE user_id = ? ORDER BY seq`, userID)
	if err != nil {
		return nil, fmt.Errorf("vault: read credentials: %w", err)
	}
	for rows.Next() {
		var c credRow
		if err := rows.Scan(&c.ID, &c.Name, &c.Username, &c.Version, &c.UpdatedAt, &c.Secret); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("vault: read credentials: %w", err)
		}
		d.creds = append(d.creds, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("vault: read credentials: %w", err)
	}
	rows, err = tx.QueryContext(ctx, `SELECT resource_id, credential_id, fingerprint, generation FROM vault_credential_assignments WHERE user_id = ? ORDER BY seq`, userID)
	if err != nil {
		return nil, fmt.Errorf("vault: read assignments: %w", err)
	}
	for rows.Next() {
		var a Assignment
		if err := rows.Scan(&a.ResourceID, &a.CredentialID, &a.Fingerprint, &a.Generation); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("vault: read assignments: %w", err)
		}
		d.assigns = append(d.assigns, a)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("vault: read assignments: %w", err)
	}
	rows, err = tx.QueryContext(ctx, `SELECT revision FROM vault_credential_imports WHERE user_id = ? ORDER BY seq`, userID)
	if err != nil {
		return nil, fmt.Errorf("vault: read imports: %w", err)
	}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("vault: read imports: %w", err)
		}
		d.imports = append(d.imports, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("vault: read imports: %w", err)
	}
	return d, nil
}

// saveDoc replaces the stored document of a user. A document beyond the
// limits is storage_limit and nothing is written.
func saveDoc(ctx context.Context, tx *store.Tx, userID int64, d *credDoc) error {
	if !d.valid() {
		return fault.New(fault.StorageLimit, "")
	}
	for _, q := range []string{
		`DELETE FROM vault_credential_assignments WHERE user_id = ?`,
		`DELETE FROM vault_credential_imports WHERE user_id = ?`,
		`DELETE FROM vault_credentials WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			return fmt.Errorf("vault: write credentials: %w", err)
		}
	}
	for i, c := range d.creds {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vault_credentials (user_id, id, seq, name, username, version, updated_at, secret)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, userID, c.ID, i, c.Name, c.Username, c.Version, c.UpdatedAt, c.Secret); err != nil {
			return fmt.Errorf("vault: write credentials: %w", err)
		}
	}
	for i, a := range d.assigns {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vault_credential_assignments (user_id, resource_id, seq, credential_id, fingerprint, generation)
VALUES (?, ?, ?, ?, ?, ?)`, userID, a.ResourceID, i, a.CredentialID, a.Fingerprint, a.Generation); err != nil {
			return fmt.Errorf("vault: write assignments: %w", err)
		}
	}
	for i, r := range d.imports {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vault_credential_imports (user_id, seq, revision) VALUES (?, ?, ?)`, userID, i, r); err != nil {
			return fmt.Errorf("vault: write imports: %w", err)
		}
	}
	return nil
}

// legacyVault is the stored automation-vault.json of a user.
type legacyVault struct {
	Version  int
	Document []byte
}

func loadLegacyVault(ctx context.Context, tx *store.Tx, userID int64) (legacyVault, bool, error) {
	var v legacyVault
	err := tx.QueryRowContext(ctx, `SELECT version, document FROM vault_legacy_automation WHERE user_id = ?`, userID).Scan(&v.Version, &v.Document)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return legacyVault{}, false, nil
	case err != nil:
		return legacyVault{}, false, fmt.Errorf("vault: read legacy vault: %w", err)
	}
	return v, true, nil
}
