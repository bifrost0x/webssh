package session

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// ResetTx ends every browser session of the database a restore
// activates and raises the installation's epoch (rotate_epoch after a
// restore of the Python release). Nothing is published: the server
// restarts with the restored database.
func ResetTx(ctx context.Context, tx *store.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE session_epoch SET value = ? WHERE singleton = 1`, randomHex(32)); err != nil {
		return fmt.Errorf("session: rotate epoch: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM session_sessions`); err != nil {
		return fmt.Errorf("session: end sessions: %w", err)
	}
	return nil
}
