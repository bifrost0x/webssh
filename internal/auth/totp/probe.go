package totp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ProbeSealed opens the first stored TOTP secret with ring and reports
// whether there was one (none without the table); a backup is verified with it (migration
// specification, section 5.9).
func ProbeSealed(ctx context.Context, tx *store.Tx, ring *keyring.Ring) (bool, error) {
	var id, userID int64
	var sealed []byte
	var tables int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'totp_authenticators'`).Scan(&tables); err != nil || tables == 0 {
		return false, err
	}
	err := tx.QueryRowContext(ctx, `SELECT id, user_id, sealed_secret FROM totp_authenticators ORDER BY id LIMIT 1`).
		Scan(&id, &userID, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("totp: read a sealed secret: %w", err)
	}
	if _, err := ring.Open(keyring.TOTP, aad("totp_authenticators", id, userID), sealed); err != nil {
		return true, fmt.Errorf("totp: open a sealed secret: %w", err)
	}
	return true, nil
}
