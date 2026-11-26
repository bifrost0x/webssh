package github

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Import and read-back for the one-time migration (E04, E06). The
// migration writes the rows of the Python release unchanged and compares
// them with what these functions return.

// ImportIdentityTx stores a legacy identity with its row id.
func ImportIdentityTx(ctx context.Context, tx *store.Tx, i Identity) error {
	if i.ID <= 0 || i.UserID <= 0 || i.GitHubUserID == "" {
		return fmt.Errorf("github: import identity: incomplete row")
	}
	_, err := insertTx(ctx, tx, i)
	return err
}

// IdentitiesTx returns every identity by row id.
func IdentitiesTx(ctx context.Context, tx *store.Tx) ([]Identity, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+identityColumns+` FROM authgithub_identities ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("github: read identities: %w", err)
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, fmt.Errorf("github: read identities: %w", err)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// ImportedConfig is the configuration row with its secret in the clear.
type ImportedConfig struct {
	Enabled       bool
	ClientID      string
	ClientSecret  []byte // nil when none is stored
	RedirectURI   string
	AutoProvision bool
	AllowedOrgs   string // allowed_orgs_json as stored
	Generation    int64
	UpdatedBy     sql.NullInt64
	UpdatedAt     time.Time
	// SecretUpdatedAt is zero for NULL.
	SecretUpdatedAt time.Time
}

// Sealer seals and opens the client secret (*keyring.Ring).
type Sealer interface {
	Seal(p keyring.Purpose, ad keyring.AAD, plain []byte) ([]byte, error)
}

// Opener opens the sealed client secret (*keyring.Ring).
type Opener interface {
	Open(p keyring.Purpose, ad keyring.AAD, sealed []byte) ([]byte, error)
}

// ImportConfigTx stores the legacy configuration, the secret sealed.
func ImportConfigTx(ctx context.Context, tx *store.Tx, seal Sealer, c ImportedConfig) error {
	row := configRow{Enabled: c.Enabled, ClientID: c.ClientID, RedirectURI: c.RedirectURI, AutoProvision: c.AutoProvision,
		AllowedOrgs: c.AllowedOrgs, Generation: c.Generation, UpdatedBy: c.UpdatedBy, UpdatedUS: c.UpdatedAt.UnixMicro()}
	if !c.SecretUpdatedAt.IsZero() {
		row.SecretUS = sql.NullInt64{Int64: c.SecretUpdatedAt.UnixMicro(), Valid: true}
	}
	if len(c.ClientSecret) > 0 {
		sealed, err := seal.Seal(keyring.GitHubClientSecret, secretAAD, c.ClientSecret)
		if err != nil {
			return fmt.Errorf("github: seal client secret: %w", err)
		}
		row.Secret = sealed
	}
	return writeConfigTx(ctx, tx, row)
}

// ImportedConfigTx reads the configuration back with its secret opened.
func ImportedConfigTx(ctx context.Context, tx *store.Tx, open Opener) (ImportedConfig, bool, error) {
	row, found, err := readConfigTx(ctx, tx)
	if err != nil || !found {
		return ImportedConfig{}, found, err
	}
	c := ImportedConfig{Enabled: row.Enabled, ClientID: row.ClientID, RedirectURI: row.RedirectURI, AutoProvision: row.AutoProvision,
		AllowedOrgs: row.AllowedOrgs, Generation: row.Generation, UpdatedBy: row.UpdatedBy, UpdatedAt: time.UnixMicro(row.UpdatedUS).UTC()}
	if row.SecretUS.Valid {
		c.SecretUpdatedAt = time.UnixMicro(row.SecretUS.Int64).UTC()
	}
	if len(row.Secret) > 0 {
		if c.ClientSecret, err = open.Open(keyring.GitHubClientSecret, secretAAD, row.Secret); err != nil {
			return ImportedConfig{}, true, fmt.Errorf("github: open client secret: %w", err)
		}
	}
	return c, true, nil
}
