package auth

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// ForgetPendingTx removes the sign-ins waiting for their second factor
// and the unused factor bootstrap codes (rotate-secret-key): both are
// stored only as MACs under the old SECRET_KEY. It returns how many it
// removed; an administrator issues a new bootstrap code where needed.
func ForgetPendingTx(ctx context.Context, tx *store.Tx) (int, error) {
	n := 0
	for _, table := range []string{"auth_pending", "auth_factor_bootstrap"} {
		res, err := tx.ExecContext(ctx, `DELETE FROM `+table) // #nosec G202 -- constant names
		if err != nil {
			return 0, fmt.Errorf("auth: clear %s: %w", table, err)
		}
		c, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("auth: clear %s: %w", table, err)
		}
		n += int(c)
	}
	return n, nil
}
