package vault

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ResealKeysTx reseals every stored SSH key for a new SECRET_KEY
// (rotate-secret-key) and returns how many it resealed.
func ResealKeysTx(ctx context.Context, tx *store.Tx, rt *keyring.Rotation) (int, error) {
	return resealTx(ctx, tx, rt, "vault_ssh_keys", "private_key", keyring.SSHKey, aad)
}

// ResealCredentialsTx reseals every saved password for a new SECRET_KEY
// and returns how many it resealed.
func ResealCredentialsTx(ctx context.Context, tx *store.Tx, rt *keyring.Rotation) (int, error) {
	return resealTx(ctx, tx, rt, "vault_credentials", "secret", keyring.Credential, credentialAAD)
}

// resealTx reseals column of table, whose rows are keyed by (user_id, id).
// The names are constants of this package.
func resealTx(ctx context.Context, tx *store.Tx, rt *keyring.Rotation, table, column string, p keyring.Purpose,
	ad func(int64, string) keyring.AAD) (int, error) {
	type row struct {
		user   int64
		id     string
		sealed []byte
	}
	rows, err := tx.QueryContext(ctx, `SELECT user_id, id, `+column+` FROM `+table+` ORDER BY user_id, id`) // #nosec G202 -- constant names
	if err != nil {
		return 0, fmt.Errorf("vault: read %s: %w", table, err)
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.user, &r.id, &r.sealed); err != nil {
			rows.Close()
			return 0, fmt.Errorf("vault: read %s: %w", table, err)
		}
		all = append(all, r)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("vault: read %s: %w", table, err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("vault: read %s: %w", table, err)
	}
	for _, r := range all {
		out, err := rt.Reseal(p, ad(r.user, r.id), r.sealed)
		if err != nil {
			return 0, fmt.Errorf("vault: reseal %s of user %d (%s): %w", table, r.user, r.id, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET `+column+` = ? WHERE user_id = ? AND id = ?`, out, r.user, r.id); err != nil { // #nosec G202 -- constant names
			return 0, fmt.Errorf("vault: write %s: %w", table, err)
		}
	}
	return len(all), nil
}
