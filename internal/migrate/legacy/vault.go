package legacy

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

// Automation vault of app/automation_vault.py: a file encrypted with the
// user's own passphrase, so the migration cannot decrypt it. Per D-06 the
// migration keeps the file and verifies its structure (Vault); the user's
// import decrypts it with the passphrase (VaultRecords).
const (
	vaultKDF      = "scrypt-131072-8-1"
	vaultN        = 131072
	vaultR        = 8
	vaultP        = 1
	vaultSaltSize = 16
	minPassphrase = 16
)

// Vault is the verified envelope of an automation vault file.
type Vault struct {
	Version    int
	salt       []byte
	nonce      []byte
	ciphertext []byte
}

// VaultRecord is one decrypted vault entry, keyed by profile id.
type VaultRecord struct {
	Fingerprint string `json:"fingerprint"`
	Password    string `json:"password"`
	Generation  string `json:"generation,omitzero"` // version 2 only
}

// ErrVaultPassphrase reports a wrong passphrase or an altered vault.
var ErrVaultPassphrase = errors.New("legacy: vault passphrase is wrong or the vault was altered")

// Vault reads and checks the vault file of a user. It returns nil when the
// user has none.
func (s *Source) Vault(userID int64) (*Vault, error) {
	name := userDir(userID) + "/automation-vault.json"
	data, err := s.readFile(name)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	doc, err := exactObject(data, "version", "kdf", "salt", "nonce", "ciphertext")
	if err != nil {
		return nil, fmt.Errorf("legacy: %s: %w", name, err)
	}
	v := &Vault{}
	kdf, okKDF := pyString(doc["kdf"])
	if json.Unmarshal(doc["version"], &v.Version) != nil || (v.Version != 1 && v.Version != 2) || !okKDF || kdf != vaultKDF {
		return nil, fmt.Errorf("legacy: %s: unsupported vault version or KDF", name)
	}
	// Lengths as app/automation_vault.py _decode and _derive check them.
	for _, f := range []struct {
		dst      *[]byte
		raw      jsontext.Value
		maxChars int
		want     int
	}{{&v.salt, doc["salt"], 32, vaultSaltSize}, {&v.nonce, doc["nonce"], 32, 12}, {&v.ciphertext, doc["ciphertext"], 900000, -1}} {
		text, ok := pyString(f.raw)
		if !ok || len(text) > f.maxChars {
			return nil, fmt.Errorf("legacy: %s: malformed vault field", name)
		}
		if *f.dst, err = base64.StdEncoding.DecodeString(text); err != nil || (f.want >= 0 && len(*f.dst) != f.want) {
			return nil, fmt.Errorf("legacy: %s: malformed vault field", name)
		}
	}
	return v, nil
}

// VaultRecords decrypts the vault of a user with the user's passphrase.
func (s *Source) VaultRecords(ctx context.Context, userID int64, v *Vault, passphrase string) (map[string]VaultRecord, error) {
	if utf8.RuneCountInString(passphrase) < minPassphrase {
		return nil, ErrVaultPassphrase
	}
	user, err := s.user(ctx, userID)
	if err != nil {
		return nil, err
	}
	incarnation, err := user.Incarnation()
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), v.salt, vaultN, vaultR, vaultP, 32)
	if err != nil {
		return nil, fmt.Errorf("legacy: derive vault key: %w", err)
	}
	aad := fmt.Sprintf("webssh-automation-vault-v%d:%d:%s", v.Version, userID, incarnation)
	raw := append(append([]byte{}, v.nonce...), v.ciphertext...)
	plain, err := openGCM(key, raw, []byte(aad))
	if err != nil {
		return nil, ErrVaultPassphrase
	}
	records, err := parseVaultRecords(plain, v.Version)
	if err != nil {
		return nil, fmt.Errorf("legacy: vault of user %d: %w", userID, err)
	}
	return records, nil
}

// parseVaultRecords applies the record checks of app/automation_vault.py
// _decrypt: at most 100 records with exactly {fingerprint, password}
// (version 1) or also generation (version 2, 64 lowercase hex), a
// fingerprint of 64 characters and a password of 1 to 4096 bytes.
func parseVaultRecords(plain []byte, version int) (map[string]VaultRecord, error) {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(plain, &raw); err != nil || raw == nil || len(raw) > 100 {
		return nil, errShape
	}
	keys := []string{"fingerprint", "password"}
	if version == 2 {
		keys = append(keys, "generation")
	}
	out := make(map[string]VaultRecord, len(raw))
	for id, value := range raw {
		rec, err := exactObject(value, keys...)
		if err != nil {
			return nil, err
		}
		var r VaultRecord
		var okF, okP bool
		r.Fingerprint, okF = pyString(rec["fingerprint"])
		r.Password, okP = pyString(rec["password"])
		if !okF || !okP || utf8.RuneCountInString(r.Fingerprint) != 64 || r.Password == "" || len(r.Password) > 4096 {
			return nil, errShape
		}
		if version == 2 {
			if r.Generation, okF = pyString(rec["generation"]); !okF || !isLowerHex(r.Generation, 64) {
				return nil, errShape
			}
		}
		out[id] = r
	}
	return out, nil
}
