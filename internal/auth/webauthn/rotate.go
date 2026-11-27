package webauthn

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// ForgetChallengesTx removes the pending passkey ceremonies
// (rotate-secret-key): their challenges are sealed under the old
// SECRET_KEY and belong to browser sessions the rotation ends. It returns
// how many it removed.
func ForgetChallengesTx(ctx context.Context, tx *store.Tx) (int, error) {
	n := 0
	for _, table := range []string{"webauthn_challenges"} {
		res, err := tx.ExecContext(ctx, `DELETE FROM `+table) // #nosec G202 -- constant names
		if err != nil {
			return 0, fmt.Errorf("webauthn: clear %s: %w", table, err)
		}
		c, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("webauthn: clear %s: %w", table, err)
		}
		n += int(c)
	}
	return n, nil
}
