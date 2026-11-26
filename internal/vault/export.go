package vault

import (
	"context"
	"errors"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Exported is one stored key as the migration's verification reads it
// back (entity E23). PEM is the opened private key; the caller compares
// it in memory and clears it.
type Exported struct {
	ID, Name, KeyType, UploadedAt string
	PublicKey, Fingerprint        string
	Usable                        bool
	PEM                           []byte
}

// ExportKeysTx returns the keys of userID in list order with their opened
// private keys.
func ExportKeysTx(ctx context.Context, tx *store.Tx, s Sealer, userID int64) ([]Exported, error) {
	rows, err := listRows(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Exported, 0, len(rows))
	for _, r := range rows {
		plain, err := s.Open(keyring.SSHKey, aad(r.UserID, r.ID), r.Sealed)
		if err != nil {
			return nil, errors.Join(errors.New("vault: export: open"), err)
		}
		out = append(out, Exported{ID: r.ID, Name: r.Name, KeyType: r.KeyType, UploadedAt: r.UploadedAt,
			PublicKey: r.PublicKey, Fingerprint: r.Fingerprint, Usable: r.State == stateUsable, PEM: plain})
	}
	return out, nil
}
