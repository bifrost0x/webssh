package legacy

import (
	"bytes"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// KeyState says whether Go can use a migrated key (migration
// specification E23 and section 4.8).
type KeyState string

const (
	// KeyUsable is a key Go parses without a passphrase.
	KeyUsable KeyState = "usable"
	// KeyUnsupported is kept sealed with its plaintext but cannot be used:
	// passphrase-protected, DSA or otherwise not loadable.
	KeyUnsupported KeyState = "unsupported"
)

// SSHKey is one stored private key with its metadata from keys.json.
type SSHKey struct {
	ID         string
	Name       string
	Filename   string
	KeyType    string // "RSA", "ECDSA" or "Ed25519" as shown in the UI
	UploadedAt string
	// PlaintextAtRest is true for a legacy key file that was never
	// encrypted. The migration encrypts it and reports it (D-05).
	PlaintextAtRest bool
	// RecoveredFrom names the pending-deletion file the key was read from
	// when its own file was missing (an interrupted deletion that Python
	// would roll back); empty otherwise.
	RecoveredFrom string
	// PEM is the private key as stored, decrypted: OpenSSH or traditional
	// PEM text, or whatever bytes an unsupported key file holds.
	PEM   []byte
	State KeyState
	// Reason explains an unsupported key; it never contains key material.
	Reason    string
	PublicKey ssh.PublicKey // nil for an unsupported key
}

// PendingDeletion is a ".delete-<token>-<filename>" entry of an
// interrupted deletion (app/key_manager.py). Python reconciles it on the
// next read with keys.json as the authority: it restores the key when
// keys.json still lists the file and the file is missing, and removes the
// entry otherwise. The migration applies the same decision in memory.
type PendingDeletion struct {
	Name     string // entry name in the key directory
	Filename string // the key file it belonged to
	Restored bool   // true: used as the key's content; false: discarded
}

// SSHKeyStore is the result of reading one user's key directory.
type SSHKeyStore struct {
	Keys    []SSHKey
	Pending []PendingDeletion
	// Unreferenced lists other files that keys.json does not name.
	Unreferenced []string
}

type keyMetadata struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Filename   string `json:"filename"`
	KeyType    string `json:"key_type"`
	Encrypted  *bool  `json:"encrypted"`
	UploadedAt string `json:"uploaded_at"`
}

type keyDocument struct {
	Keys []keyMetadata `json:"keys"`
}

// ErrKeyNeedsPassphrase reports a key protected with a passphrase.
var ErrKeyNeedsPassphrase = errors.New("legacy: private key needs a passphrase")

// SSHKeys reads keys.json of a user and every key it lists. It fails only
// where the specification says STOP: an invalid keys.json, a listed key
// whose file is missing (and not recoverable from a pending deletion), a
// key that does not decrypt, or an unsafe path. Keys that decrypt but do
// not load are returned with State KeyUnsupported.
func (s *Source) SSHKeys(userID int64) (SSHKeyStore, error) {
	var out SSHKeyStore
	dir := userDir(userID) + "/keys"
	data, err := s.readFile(dir + "/keys.json")
	if errors.Is(err, ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if _, err := decodeStore(data, keysStore); err != nil {
		return out, fmt.Errorf("legacy: %s/keys.json: %w", dir, err)
	}
	var doc keyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return out, fmt.Errorf("legacy: %s/keys.json: %w", dir, err)
	}
	entries, err := s.listDir(dir)
	if err != nil {
		return out, err
	}
	present := map[string]bool{}
	for _, e := range entries {
		present[e.Name()] = e.Type().IsRegular()
	}
	referenced := map[string]bool{"keys.json": true}
	ids := map[string]bool{}
	for _, meta := range doc.Keys {
		if !safeKeyFilename(meta.Filename) || referenced[meta.Filename] || ids[meta.ID] || meta.ID == "" {
			return out, fmt.Errorf("legacy: %s/keys.json: invalid or duplicate key entry", dir)
		}
		referenced[meta.Filename], ids[meta.ID] = true, true
	}
	restore := map[string]string{} // key filename to the pending entry Python restores
	for _, e := range entries {
		filename, ok := pendingDeleteFilename(e.Name())
		if !ok || referenced[e.Name()] {
			continue
		}
		if !present[e.Name()] {
			return out, fmt.Errorf("legacy: %s: invalid pending key deletion entry", dir)
		}
		_, taken := restore[filename]
		restored := referenced[filename] && !present[filename] && !taken
		if restored {
			restore[filename] = e.Name()
		}
		out.Pending = append(out.Pending, PendingDeletion{Name: e.Name(), Filename: filename, Restored: restored})
	}
	for _, meta := range doc.Keys {
		key, err := s.loadKey(userID, dir, meta, restore[meta.Filename])
		if err != nil {
			return out, fmt.Errorf("legacy: key %q of user %d: %w", meta.ID, userID, err)
		}
		out.Keys = append(out.Keys, key)
	}
	for _, e := range entries {
		if _, pending := pendingDeleteFilename(e.Name()); !referenced[e.Name()] && !pending {
			out.Unreferenced = append(out.Unreferenced, e.Name())
		}
	}
	return out, nil
}

// pendingDeleteFilename mirrors app/key_manager.py _pending_delete_filename.
func pendingDeleteFilename(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, ".delete-")
	if !ok {
		return "", false
	}
	token, filename, ok := strings.Cut(rest, "-")
	if !ok || len(token) != 32 || strings.Trim(token, "0123456789abcdef") != "" || !safeKeyFilename(filename) {
		return "", false
	}
	return filename, true
}

// safeKeyFilename mirrors app/key_manager.py _is_safe_key_filename.
func safeKeyFilename(name string) bool {
	return name != "" && name != "." && name != ".." && name != "keys.json" &&
		!strings.ContainsAny(name, "/\\\x00")
}

func (s *Source) loadKey(userID int64, dir string, meta keyMetadata, pending string) (SSHKey, error) {
	file := meta.Filename
	if pending != "" {
		file = pending
	}
	content, err := s.readFile(dir + "/" + file)
	if err != nil {
		return SSHKey{}, err
	}
	key := SSHKey{ID: meta.ID, Name: meta.Name, Filename: meta.Filename, KeyType: meta.KeyType,
		UploadedAt: meta.UploadedAt, RecoveredFrom: pending}
	if isFernetToken(content) {
		if key.PEM, err = s.decryptFernet(sshKeyPurpose, userID, content); err != nil {
			return SSHKey{}, err
		}
	} else {
		key.PEM, key.PlaintextAtRest = content, true
	}
	key.State, key.PublicKey, key.Reason = KeyUsable, nil, ""
	if !utf8.Valid(key.PEM) {
		key.State, key.Reason = KeyUnsupported, "key is not text"
		return key, nil
	}
	if key.PublicKey, err = parsePrivateKey(key.PEM); err != nil {
		key.State, key.Reason = KeyUnsupported, unsupportedReason(err)
	}
	return key, nil
}

func unsupportedReason(err error) string {
	if errors.Is(err, ErrKeyNeedsPassphrase) {
		return "protected with a passphrase"
	}
	return "key type or format not supported"
}

// isFernetToken mirrors app/key_encryption.py is_encrypted: PEM text is
// plaintext; otherwise a URL-safe base64 value of at least 73 bytes that
// starts with the Fernet version byte is a token.
func isFernetToken(data []byte) bool {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) || len(data) < 50 {
		return false
	}
	raw, err := base64.URLEncoding.DecodeString(string(data))
	return err == nil && len(raw) >= 73 && raw[0] == 0x80
}

// parsePrivateKey parses a private key and returns its public key.
func parsePrivateKey(pem []byte) (ssh.PublicKey, error) {
	signer, err := ssh.ParsePrivateKey(pem)
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		return nil, ErrKeyNeedsPassphrase
	}
	if err != nil {
		return nil, fmt.Errorf("legacy: unsupported private key: %w", err)
	}
	return signer.PublicKey(), nil
}
