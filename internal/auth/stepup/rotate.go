package stepup

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// ForgetTx removes every step-up intent and grant (rotate-secret-key):
// they are stored only as MACs under the old SECRET_KEY. It returns how
// many it removed.
func ForgetTx(ctx context.Context, tx *store.Tx) (int, error) {
	n := 0
	for _, table := range []string{"stepup_grants", "stepup_intents"} {
		res, err := tx.ExecContext(ctx, `DELETE FROM `+table) // #nosec G202 -- constant names
		if err != nil {
			return 0, fmt.Errorf("stepup: clear %s: %w", table, err)
		}
		c, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("stepup: clear %s: %w", table, err)
		}
		n += int(c)
	}
	return n, nil
}
