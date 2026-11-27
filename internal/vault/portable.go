package vault

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// portableTables are the vault tables a portable export leaves out, in an
// order that respects the foreign keys: saved passwords with their
// assignments and import records, the legacy automation vault and the SSH
// private keys (the Python export drops keys/, credentials.json* and
// automation-vault.json*, app/backup_manager.py
// _excluded_remote_credential_path).
var portableTables = []string{
	"vault_credential_assignments", "vault_credentials", "vault_credential_imports",
	"vault_legacy_automation", "vault_ssh_keys",
}

// DropRemoteCredentialsTx removes every saved password and SSH private key
// from the database of a portable export or of a restored export, and
// reports how many rows it removed. A database without the vault tables
// has nothing to remove. The caller vacuums the database afterwards, so
// that the removed records leave no trace in free pages.
func DropRemoteCredentialsTx(ctx context.Context, tx *store.Tx) (int64, error) {
	var n int64
	for _, table := range portableTables {
		var present int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&present); err != nil {
			return n, fmt.Errorf("vault: inspect %s: %w", table, err)
		}
		if present == 0 {
			continue
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM `+table) // #nosec G202 -- table names from the fixed list above
		if err != nil {
			return n, fmt.Errorf("vault: clear %s: %w", table, err)
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return n, fmt.Errorf("vault: clear %s: %w", table, err)
		}
		n += rows
	}
	return n, nil
}
