package github

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ResealTx reseals the stored client secret for a new SECRET_KEY
// (rotate-secret-key) and returns 1 when there is one. Pending sign-in
// flights are kept only as MACs under the old key; they are removed, and a
// sign-in in progress starts again.
func ResealTx(ctx context.Context, tx *store.Tx, rt *keyring.Rotation) (int, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM authgithub_flights`); err != nil {
		return 0, fmt.Errorf("github: remove pending sign-ins: %w", err)
	}
	var sealed []byte
	err := tx.QueryRowContext(ctx, `SELECT client_secret FROM authgithub_config WHERE singleton = 1`).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && sealed == nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("github: read the client secret: %w", err)
	}
	out, err := rt.Reseal(keyring.GitHubClientSecret, secretAAD, sealed)
	if err != nil {
		return 0, fmt.Errorf("github: reseal the client secret: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authgithub_config SET client_secret = ? WHERE singleton = 1`, out); err != nil {
		return 0, fmt.Errorf("github: write the client secret: %w", err)
	}
	return 1, nil
}
