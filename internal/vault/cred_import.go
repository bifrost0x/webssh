package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ImportedCredential is one saved password of credentials.json as the
// migration (E32) read it. Values are kept verbatim; Password is cleared
// by ImportCredentialTx.
type ImportedCredential struct {
	UserID    int64
	ID        string
	Name      string
	Username  string
	Version   string
	UpdatedAt string
	Password  []byte
}

// ImportCredentialTx stores a migrated password after the user's other
// passwords, sealed for its row.
func ImportCredentialTx(ctx context.Context, tx *store.Tx, sealer Sealer, c ImportedCredential) error {
	defer clear(c.Password)
	if c.UserID <= 0 || c.ID == "" {
		return errors.New("vault: imported credential without owner or id")
	}
	sealed, err := sealer.Seal(keyring.Credential, credentialAAD(c.UserID, c.ID), c.Password)
	if err != nil {
		return fmt.Errorf("vault: seal imported credential: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO vault_credentials (user_id, id, seq, name, username, version, updated_at, secret)
VALUES (?, ?, (SELECT coalesce(max(seq), -1) + 1 FROM vault_credentials WHERE user_id = ?), ?, ?, ?, ?, ?)`,
		c.UserID, c.ID, c.UserID, c.Name, c.Username, c.Version, c.UpdatedAt, sealed)
	if err != nil {
		return fmt.Errorf("vault: import credential: %w", err)
	}
	return nil
}

// ImportAssignmentsTx stores the migrated assignments of a user in their
// order, with their fingerprint and generation unchanged, and the legacy
// vault documents the user had imported. Every assignment must name an
// imported credential.
func ImportAssignmentsTx(ctx context.Context, tx *store.Tx, userID int64, assignments []Assignment, imports []string) error {
	for i, a := range assignments {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vault_credential_assignments (user_id, resource_id, seq, credential_id, fingerprint, generation)
VALUES (?, ?, ?, ?, ?, ?)`, userID, a.ResourceID, i, a.CredentialID, a.Fingerprint, a.Generation); err != nil {
			return fmt.Errorf("vault: import assignment: %w", err)
		}
	}
	for i, r := range imports {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vault_credential_imports (user_id, seq, revision) VALUES (?, ?, ?)`, userID, i, r); err != nil {
			return fmt.Errorf("vault: import imports: %w", err)
		}
	}
	return nil
}

// ExportedCredential is a stored password opened for the migration's
// verification; the caller clears Password.
type ExportedCredential struct {
	ID, Name, Username, Version, UpdatedAt string
	Password                               []byte
}

// Opener opens sealed values (*keyring.Ring).
type Opener interface {
	Open(p keyring.Purpose, ad keyring.AAD, sealed []byte) ([]byte, error)
}

// ExportCredentialsTx reads a user's passwords (opened), assignments and
// imports back in their stored order.
func ExportCredentialsTx(ctx context.Context, tx *store.Tx, open Opener, userID int64) ([]ExportedCredential, []Assignment, []string, error) {
	d, err := loadDoc(ctx, tx, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	out := make([]ExportedCredential, 0, len(d.creds))
	for _, c := range d.creds {
		plain, err := open.Open(keyring.Credential, credentialAAD(userID, c.ID), c.Secret)
		if err != nil {
			for _, e := range out {
				clear(e.Password)
			}
			return nil, nil, nil, fmt.Errorf("vault: open credential %q: %w", c.ID, err)
		}
		out = append(out, ExportedCredential{ID: c.ID, Name: c.Name, Username: c.Username, Version: c.Version, UpdatedAt: c.UpdatedAt, Password: plain})
	}
	return out, d.assigns, d.imports, nil
}

// ImportLegacyVaultTx keeps a user's automation-vault.json byte for byte
// (E30, D-06); the user imports it with its passphrase.
func ImportLegacyVaultTx(ctx context.Context, tx *store.Tx, userID int64, document []byte, version int) error {
	if userID <= 0 || (version != 1 && version != 2) || len(document) == 0 {
		return errors.New("vault: invalid legacy vault")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vault_legacy_automation (user_id, version, document) VALUES (?, ?, ?)`, userID, version, document); err != nil {
		return fmt.Errorf("vault: import legacy vault: %w", err)
	}
	return nil
}

// ExportLegacyVaultTx reads a kept legacy vault back.
func ExportLegacyVaultTx(ctx context.Context, tx *store.Tx, userID int64) (document []byte, version int, found bool, err error) {
	v, found, err := loadLegacyVault(ctx, tx, userID)
	return v.Document, v.Version, found, err
}

// CheckLegacyVault applies the structure checks the import applies before
// it asks for the passphrase; the migration runs it so a vault that could
// never be imported is reported.
func CheckLegacyVault(document []byte) (version int, err error) {
	e, err := parseLegacyVault(document)
	return e.version, err
}
