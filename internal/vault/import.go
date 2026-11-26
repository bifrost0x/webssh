package vault

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Imported is one SSH key of the Python release (entity E23): the
// metadata of keys.json and the decrypted key file.
type Imported struct {
	ID         string
	UserID     int64
	Name       string
	KeyType    string // as keys.json says; shown and compared on replace
	UploadedAt string // verbatim
	PEM        []byte // the private key without Fernet; cleared on return
}

// ImportKey stores a migrated key in the migration's transaction. Call it
// in the order of keys.json; that order is the list order. A key WebSSH
// cannot load (passphrase-protected or DSA material of old releases) is
// stored sealed with state 'unsupported' and is listed as unusable.
// publicKey is the authorized_keys line of a usable key, for the
// migration's verification; it is empty otherwise.
func ImportKey(ctx context.Context, tx *store.Tx, s Sealer, k Imported) (publicKey string, err error) {
	defer clear(k.PEM)
	if k.UserID <= 0 {
		return "", errors.New("vault: import: invalid user")
	}
	r := keyRow{ID: k.ID, UserID: k.UserID, Name: k.Name, KeyType: k.KeyType, UploadedAt: k.UploadedAt, State: stateUnsupported}
	if key, err := parseKey(k.PEM, nil); err == nil {
		pub := key.signer.PublicKey()
		r.PublicKey = strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
		r.Fingerprint = ssh.FingerprintSHA256(pub)
		r.State = stateUsable
	}
	// The file is sealed as it was, also when it cannot be loaded, so a
	// later release that supports it needs no second migration.
	r.Sealed, err = s.Seal(keyring.SSHKey, aad(r.UserID, r.ID), k.PEM)
	if err != nil {
		return "", errors.Join(errors.New("vault: import: seal"), err)
	}
	if err := insertRow(ctx, tx, r); err != nil {
		return "", err
	}
	return r.PublicKey, nil
}
