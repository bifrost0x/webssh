package accounts

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// RaiseAllGenerationsTx raises every account's auth_generation once, in
// the database a restore activates: every credential issued under the old
// generations ends (sessions, pending sign-ins, step-up grants, factor
// bootstrap codes, known-device cookies) and schedule approvals must be
// renewed, as after a restore of the Python release
// (restore_sanitizer.py).
func RaiseAllGenerationsTx(ctx context.Context, tx *store.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE accounts_users SET auth_generation = auth_generation + 1`); err != nil {
		return fmt.Errorf("accounts: raise generations: %w", err)
	}
	return nil
}
