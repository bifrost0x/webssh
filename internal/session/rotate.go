package session

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// EndAllTx removes every browser session (rotate-secret-key): their
// tokens are stored only as MACs under the old SECRET_KEY and can neither
// be converted nor checked any more. It returns how many it removed. The
// rotation runs while no server serves the database, so nothing is
// journaled; every user signs in again.
func EndAllTx(ctx context.Context, tx *store.Tx) (int, error) {
	n := 0
	for _, table := range []string{"session_sessions"} {
		res, err := tx.ExecContext(ctx, `DELETE FROM `+table) // #nosec G202 -- constant names
		if err != nil {
			return 0, fmt.Errorf("session: clear %s: %w", table, err)
		}
		c, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("session: clear %s: %w", table, err)
		}
		n += int(c)
	}
	return n, nil
}
