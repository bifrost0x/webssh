package totp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ExportTx reads a stored authenticator back with its opened secret, for
// the migration's verification (entity E08). The secret is returned to
// be compared in memory and discarded.
func (s *Service) ExportTx(ctx context.Context, tx *store.Tx, id int64) (Imported, error) {
	var a Imported
	var sealed []byte
	var created int64
	var activated, used sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id, user_id, label, sealed_secret, active, last_accepted_step, created_at, activated_at, last_used_at
		FROM totp_authenticators WHERE id = ?`, id).Scan(&a.ID, &a.UserID, &a.Label, &sealed, &a.Active, &a.LastAcceptedStep,
		&created, &activated, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return Imported{}, fmt.Errorf("totp: authenticator %d not found", id)
	}
	if err != nil {
		return Imported{}, fmt.Errorf("totp: read authenticator %d: %w", id, err)
	}
	if _, err := s.open("totp_authenticators", a.ID, a.UserID, sealed); err != nil {
		return Imported{}, err
	}
	plain, err := s.Ring.Open(keyring.TOTP, aad("totp_authenticators", a.ID, a.UserID), sealed)
	if err != nil {
		return Imported{}, fmt.Errorf("totp: open secret: %w", err)
	}
	a.Base32 = string(plain)
	clear(plain)
	a.CreatedAt = time.UnixMicro(created).UTC()
	if activated.Valid {
		a.ActivatedAt = time.UnixMicro(activated.Int64).UTC()
	}
	if used.Valid {
		a.LastUsedAt = time.UnixMicro(used.Int64).UTC()
	}
	return a, nil
}
