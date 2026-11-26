//go:build e2e

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"github.com/bifrost0x/webssh/internal/auth/webauthn"
	"github.com/bifrost0x/webssh/internal/store"
)

func init() {
	passkeyPlaceholder = func(svc *webauthn.Service) func(ctx context.Context, userID int64, name, credentialID string, transports []string) error {
		return func(ctx context.Context, userID int64, name, credentialID string, transports []string) error {
			cose, err := unusablePasskeyKey()
			if err != nil {
				return err
			}
			return svc.DB.Write(ctx, func(tx *store.Tx) error {
				var id int64
				if err := tx.QueryRowContext(ctx, `SELECT coalesce(max(id), 0) + 1 FROM webauthn_credentials`).Scan(&id); err != nil {
					return err
				}
				return svc.ImportTx(ctx, tx, webauthn.Imported{ID: id, UserID: userID, CredentialID: []byte(credentialID),
					COSEKey: cose, Transports: transports, Name: name, CreatedAt: time.Now()})
			})
		}
	}
}

// unusablePasskeyKey is the COSE form of a fresh Ed25519 public key whose
// private half is dropped: the placeholder marks the account as enrolled
// and never authenticates.
func unusablePasskeyKey() ([]byte, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x}
	out := []byte{0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20}
	return append(out, pub...), nil
}
