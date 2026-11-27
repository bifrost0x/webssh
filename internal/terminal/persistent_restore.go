package terminal

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// ForgetPersistentTx removes the names of persistent tmux sessions from
// the database a restore activates: the restored state never offers a
// session that belongs to another moment (A01; Python's restore empties
// ssh_sessions). The sessions on the hosts are not touched.
func ForgetPersistentTx(ctx context.Context, tx *store.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM terminal_persistent_sessions`); err != nil {
		return fmt.Errorf("terminal: forget persistent sessions: %w", err)
	}
	return nil
}
