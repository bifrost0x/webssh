package legacy

import (
	"context"
	json "encoding/json/v2"
	"fmt"

	"github.com/bifrost0x/webssh/internal/auth/webauthn"
)

// Passkey is one row of webauthn_credentials with its parsed COSE key.
type Passkey struct {
	ID           int64
	UserID       int64
	CredentialID []byte
	// COSEKey is the stored COSE_Key, unchanged. The migration keeps these
	// bytes; PublicKey proves they parse.
	COSEKey   []byte
	PublicKey webauthn.PublicKey // parsed by the passkey capability
	SignCount  int64
	Transports []string
	Name       string
	CreatedAt  string
}

// Passkeys reads every WebAuthn credential and parses its public key.
func (s *Source) Passkeys(ctx context.Context) ([]Passkey, error) {
	if !s.schema.HasTable("webauthn_credentials") {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, credential_id, public_key, sign_count, transports, name,
		CAST(created_at AS TEXT) FROM webauthn_credentials ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read passkeys: %w", err)
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		var transports string
		if err := rows.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.COSEKey, &p.SignCount, &transports, &p.Name, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("legacy: read passkeys: %w", err)
		}
		if err := json.Unmarshal([]byte(transports), &p.Transports); err != nil {
			return nil, fmt.Errorf("legacy: passkey %d: transports: %w", p.ID, err)
		}
		if p.PublicKey, err = webauthn.ParseCOSEKey(p.COSEKey); err != nil {
			return nil, fmt.Errorf("legacy: passkey %d: %w", p.ID, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

