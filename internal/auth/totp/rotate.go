package totp

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ResealTx reseals every authenticator secret for a new SECRET_KEY
// (rotate-secret-key) and returns how many it resealed. Pending
// enrollments belong to browser sessions, which the rotation ends; they
// are removed and the user starts the enrollment again.
func ResealTx(ctx context.Context, tx *store.Tx, rt *keyring.Rotation) (int, error) {
	type row struct {
		id, user int64
		sealed   []byte
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, user_id, sealed_secret FROM totp_authenticators ORDER BY id`)
	if err != nil {
		return 0, fmt.Errorf("totp: read authenticators: %w", err)
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.user, &r.sealed); err != nil {
			rows.Close()
			return 0, fmt.Errorf("totp: read authenticators: %w", err)
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("totp: read authenticators: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("totp: read authenticators: %w", err)
	}
	for _, r := range all {
		out, err := rt.Reseal(keyring.TOTP, aad("totp_authenticators", r.id, r.user), r.sealed)
		if err != nil {
			return 0, fmt.Errorf("totp: reseal authenticator %d of user %d: %w", r.id, r.user, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE totp_authenticators SET sealed_secret = ? WHERE id = ?`, out, r.id); err != nil {
			return 0, fmt.Errorf("totp: write authenticator %d: %w", r.id, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_enrollments`); err != nil {
		return 0, fmt.Errorf("totp: remove pending enrollments: %w", err)
	}
	return len(all), nil
}
