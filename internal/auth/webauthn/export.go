package webauthn

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// ImportedTx returns the stored passkeys of userID in id order in the form
// ImportTx takes, for the migration's verification (entity E10).
func ImportedTx(ctx context.Context, tx *store.Tx, userID int64) ([]Imported, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, user_id, credential_id, public_key, sign_count, transports, name, created_at,
		last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: read passkeys: %w", err)
	}
	defer rows.Close()
	var out []Imported
	for rows.Next() {
		var p Imported
		var transports string
		var created int64
		var used *int64
		if err := rows.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.COSEKey, &p.SignCount, &transports, &p.Name, &created, &used); err != nil {
			return nil, fmt.Errorf("webauthn: read passkeys: %w", err)
		}
		if err := json.Unmarshal([]byte(transports), &p.Transports); err != nil {
			return nil, fmt.Errorf("webauthn: passkey %d: transports: %w", p.ID, err)
		}
		p.CreatedAt = time.UnixMicro(created).UTC()
		if used != nil {
			p.LastUsedAt = time.UnixMicro(*used).UTC()
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
