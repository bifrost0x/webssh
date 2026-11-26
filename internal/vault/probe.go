package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ProbeSealed opens the first stored SSH key with ring and reports
// whether there was one (none without the table). A backup is verified with it: the key must
// decrypt with the SECRET_KEY and keyring material the backup carries
// (migration specification, section 5.9).
func ProbeSealed(ctx context.Context, tx *store.Tx, ring *keyring.Ring) (bool, error) {
	var userID int64
	var id string
	var sealed []byte
	var tables int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'vault_ssh_keys'`).Scan(&tables); err != nil || tables == 0 {
		return false, err
	}
	err := tx.QueryRowContext(ctx, `SELECT user_id, id, private_key FROM vault_ssh_keys ORDER BY user_id, seq LIMIT 1`).
		Scan(&userID, &id, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("vault: read a sealed key: %w", err)
	}
	if _, err := ring.Open(keyring.SSHKey, aad(userID, id), sealed); err != nil {
		return true, fmt.Errorf("vault: open a sealed key: %w", err)
	}
	return true, nil
}
