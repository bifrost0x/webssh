package auth

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// RecoveryHashesTx returns the stored recovery code hashes of userID in
// insertion order, for the migration's verification (entity E11).
func RecoveryHashesTx(ctx context.Context, tx *store.Tx, userID int64) ([][]byte, error) {
	rows, err := tx.QueryContext(ctx, `SELECT hash FROM auth_recovery_codes WHERE user_id = ? AND algorithm = ? ORDER BY id`,
		userID, RecoveryAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("auth: read recovery codes: %w", err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("auth: read recovery codes: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ThrottleTx returns the stored code backoff of userID for scope, for the
// migration's verification (entity E01).
func ThrottleTx(ctx context.Context, tx *store.Tx, userID int64, scope Scope) (failures int, lastFailedUS int64, err error) {
	var last *int64
	err = tx.QueryRowContext(ctx, `SELECT failures, last_failed_at FROM auth_mfa_throttle WHERE user_id = ? AND scope = ?`,
		userID, string(scope)).Scan(&failures, &last)
	if err != nil {
		return 0, 0, err
	}
	if last != nil {
		lastFailedUS = *last
	}
	return failures, lastFailedUS, nil
}
