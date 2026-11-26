package legacy

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// sshKeysStep migrates entity E23 with A08: the private keys of every
// account in the order of keys.json, decrypted with the per-user Fernet
// key (or read as plaintext from old releases) and sealed through
// vault.ImportKey. Interrupted deletions are reconciled as Python does.
// Keys this release cannot use (passphrase-protected, DSA, RSA below 1024
// bits) are kept sealed as unsupported and named in the report
// (specification 4.8).
type sshKeysStep struct {
	users []userKeys
}

type userKeys struct {
	id    int64
	store SSHKeyStore
	// unsupported are the keys the vault stored as unsupported, with why.
	unsupported map[string]string
}

func (*sshKeysStep) Entity() string { return "E23" }

func (*sshKeysStep) Version() int { return 1 }

func (s *sshKeysStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		ks, err := src.SSHKeys(a.ID)
		if err != nil {
			return &StepError{UserID: a.ID, Record: "keys/keys.json", Err: err}
		}
		for _, k := range ks.Keys {
			if strings.ContainsRune(k.ID, 0) {
				return &StepError{UserID: a.ID, Record: "keys/keys.json", Err: errors.New("legacy: a key id holds a NUL byte")}
			}
		}
		s.users = append(s.users, userKeys{id: a.ID, store: ks, unsupported: map[string]string{}})
	}
	return nil
}

// sealOpener is the keyring as the vault needs it.
type sealOpener interface {
	Sealer
	Opener
}

func (s *sshKeysStep) Write(ctx context.Context, tx *store.Tx, seal Sealer) error {
	ring, ok := seal.(sealOpener)
	if !ok {
		return fmt.Errorf("legacy: %T cannot open sealed keys", seal)
	}
	for _, u := range s.users {
		for _, k := range u.store.Keys {
			pem := bytes.Clone(k.PEM) // ImportKey clears what it gets
			pub, err := vault.ImportKey(ctx, tx, ring, vault.Imported{ID: k.ID, UserID: u.id, Name: k.Name,
				KeyType: k.KeyType, UploadedAt: k.UploadedAt, PEM: pem})
			if err != nil {
				return &StepError{UserID: u.id, Record: k.ID, Err: err}
			}
			if pub == "" {
				u.unsupported[k.ID] = unusableReason(k)
			}
		}
	}
	return nil
}

// unusableReason names why a key cannot be used, without key material.
func unusableReason(k SSHKey) string {
	if k.State == KeyUnsupported {
		return k.Reason
	}
	switch k.PublicKey.Type() {
	case ssh.KeyAlgoDSA:
		return "DSA keys are not supported"
	case ssh.KeyAlgoRSA:
		if raw, err := ssh.ParseRawPrivateKey(k.PEM); err == nil {
			if rk, ok := raw.(*rsa.PrivateKey); ok && rk.N.BitLen() < 1024 {
				return fmt.Sprintf("RSA key with %d bits: below 1024 bits, which this release cannot sign with; OpenSSH has refused such keys since 7.6", rk.N.BitLen())
			}
		}
	}
	return "key type or format not supported"
}

// Verify opens every stored key and compares it with the legacy file:
// order, id, name, type and upload time; the private key byte for byte;
// for a usable key the public key equals the one the legacy key yields.
func (s *sshKeysStep) Verify(ctx context.Context, tx *store.Tx, open Opener) error {
	ring, ok := open.(sealOpener)
	if !ok {
		return fmt.Errorf("legacy: %T cannot open sealed keys", open)
	}
	for _, u := range s.users {
		got, err := vault.ExportKeysTx(ctx, tx, ring, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if len(got) != len(u.store.Keys) {
			return &StepError{UserID: u.id, Err: errors.New("legacy: the number of stored keys differs")}
		}
		for i, k := range u.store.Keys {
			g := got[i]
			same := g.ID == k.ID && g.Name == k.Name && g.KeyType == k.KeyType && g.UploadedAt == k.UploadedAt && bytes.Equal(g.PEM, k.PEM)
			clear(g.PEM)
			_, unusable := u.unsupported[k.ID]
			if g.Usable {
				same = same && !unusable && k.PublicKey != nil &&
					g.PublicKey == strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(k.PublicKey)), "\n") &&
					g.Fingerprint == ssh.FingerprintSHA256(k.PublicKey)
			} else {
				same = same && unusable
			}
			if !same {
				return &StepError{UserID: u.id, Record: k.ID, Err: errors.New("legacy: the stored key differs from the legacy key")}
			}
		}
	}
	return nil
}

func (s *sshKeysStep) Report() StepReport {
	r := StepReport{Entity: "E23", Version: 1}
	plaintext := 0
	for _, u := range s.users {
		r.Read += len(u.store.Keys)
		r.Written += len(u.store.Keys)
		for _, k := range u.store.Keys {
			if reason, ok := u.unsupported[k.ID]; ok {
				r.Flagged = append(r.Flagged, Flag{UserID: u.id, ID: k.ID, Reason: "unsupported: " + reason})
			}
			if k.PlaintextAtRest {
				plaintext++
				r.Warnings = append(r.Warnings, Warning{Code: "plaintext_key_sealed", UserID: u.id,
					Message: "the key " + k.ID + " was stored unencrypted by an old release; it is now sealed, and the unencrypted file is removed by webssh legacy purge"})
			}
			if k.RecoveredFrom != "" {
				r.Notes = append(r.Notes, fmt.Sprintf("user %d: key %s restored from an interrupted deletion, as the Python release does", u.id, k.ID))
			}
		}
		for _, p := range u.store.Pending {
			if !p.Restored {
				r.KeptInPlace = append(r.KeptInPlace, KeptPath{Path: userDir(u.id) + "/keys/" + p.Name, Reason: "interrupted_key_deletion"})
			}
		}
		for _, name := range u.store.Unreferenced {
			r.KeptInPlace = append(r.KeptInPlace, KeptPath{Path: userDir(u.id) + "/keys/" + name, Reason: "not_listed_in_keys_json"})
		}
		if u.store.LoneSurrogates {
			r.Flagged = append(r.Flagged, Flag{UserID: u.id, ID: "keys.json", Reason: "lone_surrogate"})
		}
		if u.store.DuplicateNames {
			r.Flagged = append(r.Flagged, Flag{UserID: u.id, ID: "keys.json", Reason: "duplicate_member_name"})
		}
	}
	if plaintext > 0 {
		r.Notes = append(r.Notes, "unencrypted legacy key files remain until webssh legacy purge; an audit event is due for each sealed one")
	}
	return r
}
