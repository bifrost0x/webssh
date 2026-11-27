package legacy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// NamedCredential is one decrypted entry of credentials.json.
type NamedCredential struct {
	ID        string
	Name      string
	Username  string
	Version   string
	UpdatedAt string
	Password  string

	ciphertext string
}

// CredentialAssignment binds a saved host to a named credential.
type CredentialAssignment struct {
	CredentialID string `json:"credential_id"`
	Fingerprint  string `json:"fingerprint"`
	Generation   string `json:"generation"`
}

// NamedCredentials reads and decrypts credentials.json of a user
// (app/credential_store.py, app/credential_crypto.py). The key is
// HKDF-SHA256(SECRET_KEY, salt "webssh-named-credential-master-v1",
// info = context) and the context is also the AES-GCM additional data.
func (s *Source) NamedCredentials(ctx context.Context, userID int64) ([]NamedCredential, map[string]CredentialAssignment, error) {
	name := userDir(userID) + "/credentials.json"
	data, err := s.readStoreBytes(name, "credentials")
	if errors.Is(err, ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	records, assignments, err := parseCredentialDocument(data)
	if err != nil {
		return nil, nil, fmt.Errorf("legacy: %s: %w", name, err)
	}
	user, err := s.user(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	incarnation, err := user.Incarnation()
	if err != nil {
		return nil, nil, err
	}
	var out []NamedCredential
	for _, rec := range records {
		password, err := decryptNamedCredential(s.secret, userID, incarnation, rec.ID, rec.ciphertext)
		if err != nil {
			return nil, nil, &StepError{UserID: userID, Record: "credential " + rec.ID,
				Err: fmt.Errorf("legacy: credential %q of user %d: %w", rec.ID, userID, err)}
		}
		rec.Password = password
		out = append(out, rec)
	}
	return out, assignments, nil
}

// namedCredentialContext is the compact JSON array of
// app/credential_crypto.py _context.
func namedCredentialContext(userID int64, incarnation, recordID string) ([]byte, error) {
	text, err := pythonCompactJSON("webssh-named-credentials-v1", userID, incarnation, recordID)
	return []byte(text), err
}

func decryptNamedCredential(secret string, userID int64, incarnation, recordID, ciphertext string) (string, error) {
	context, err := namedCredentialContext(userID, incarnation, recordID)
	if err != nil {
		return "", err
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte("webssh-named-credential-master-v1"), string(context), 32)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(ciphertext)
	if err != nil {
		return "", errors.New("ciphertext is not base64")
	}
	plain, err := openGCM(key, raw, context)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrRecordDamaged, err)
	}
	return string(plain), nil
}

// openGCM decrypts nonce(12) || ciphertext || tag with AES-256-GCM.
func openGCM(key, raw, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("ciphertext does not authenticate")
	}
	return plain, nil
}

// parseCredentialDocument applies app/credential_store.py _valid exactly:
// member sets, limits, text rules, ids and assignment references.
func parseCredentialDocument(data []byte) ([]NamedCredential, map[string]CredentialAssignment, error) {
	doc, err := exactObject(data, "version", "credentials", "assignments", "imports")
	if err != nil {
		return nil, nil, err
	}
	var credentials, assignments map[string]jsontext.Value
	var imports []jsontext.Value
	if !pyjson.EqualsOne(doc["version"]) ||
		json.Unmarshal(doc["credentials"], &credentials) != nil || credentials == nil || len(credentials) > 100 ||
		json.Unmarshal(doc["assignments"], &assignments) != nil || assignments == nil || len(assignments) > 1000 ||
		json.Unmarshal(doc["imports"], &imports) != nil || imports == nil || len(imports) > 100 {
		return nil, nil, errShape
	}
	var out []NamedCredential
	for _, id := range slices.Sorted(maps.Keys(credentials)) {
		rec, err := exactObject(credentials[id], "id", "name", "username", "version", "updated_at", "ciphertext")
		if err != nil {
			return nil, nil, err
		}
		var c NamedCredential
		var ok [6]bool
		c.ID, ok[0] = pyString(rec["id"])
		c.Name, ok[1] = pyText(rec["name"], 128, false)
		c.Username, ok[2] = pyString(rec["username"])
		c.Version, ok[3] = pyText(rec["version"], 64, false)
		// Python does not check updated_at; a non-string value is kept as
		// its JSON text.
		if c.UpdatedAt, ok[4] = pyString(rec["updated_at"]); !ok[4] {
			c.UpdatedAt, ok[4] = string(rec["updated_at"]), true
		}
		c.ciphertext, ok[5] = pyText(rec["ciphertext"], 8192, false)
		if slices.Contains(ok[:], false) || c.ID != id {
			return nil, nil, errShape
		}
		out = append(out, c)
	}
	refs := make(map[string]CredentialAssignment, len(assignments))
	for resource, raw := range assignments {
		a, err := exactObject(raw, "credential_id", "fingerprint", "generation")
		if err != nil {
			return nil, nil, err
		}
		var c CredentialAssignment
		var ok1, ok2, ok3 bool
		c.CredentialID, ok1 = pyString(a["credential_id"])
		c.Fingerprint, ok2 = pyString(a["fingerprint"])
		c.Generation, ok3 = pyString(a["generation"])
		if _, known := credentials[c.CredentialID]; !ok1 || !ok2 || !ok3 || !known {
			return nil, nil, errShape
		}
		refs[resource] = c
	}
	return out, refs, nil
}
