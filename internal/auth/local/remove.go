package local

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// RemoveTx deletes the local password of an account that a directory
// manages from now on, so no dormant password stays behind (an LDAP link
// destroyed it in the Python release too). Removing a missing password is
// not an error.
func RemoveTx(ctx context.Context, tx *store.Tx, userID int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM authlocal_passwords WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("local: remove password: %w", err)
	}
	return nil
}
