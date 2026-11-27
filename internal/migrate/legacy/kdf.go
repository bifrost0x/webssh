package legacy

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/fernet"
)

// Key derivations of the Python release. Each Fernet key is
// PBKDF2-HMAC-SHA256(password, salt, 600000 iterations, 32 bytes); the
// password embeds SECRET_KEY and the purpose.
const pbkdf2Iterations = 600_000

type fernetPurpose struct {
	salt     string
	password func(secret string, userID int64) string
}

var (
	// app/key_encryption.py _derive_key
	sshKeyPurpose = fernetPurpose{"webssh_key_encryption_v1", func(s string, id int64) string { return fmt.Sprintf("%s:%d", s, id) }}
	// app/mfa_crypto.py
	totpPurpose = fernetPurpose{"webssh-mfa-totp-v1", func(s string, id int64) string { return fmt.Sprintf("%s:totp:%d", s, id) }}
	// app/github_auth_crypto.py
	githubPurpose = fernetPurpose{"webssh-github-auth-config-v1", func(s string, _ int64) string { return s + ":github-auth:configuration" }}
)

// fernetKey derives, once per purpose and user, the Fernet key. PBKDF2 at
// 600000 iterations is slow on purpose, so results are cached for the life
// of the Source.
func (s *Source) fernetKey(p fernetPurpose, userID int64) (*fernet.Key, error) {
	cacheKey := fmt.Sprintf("%s\x00%d", p.salt, userID)
	s.mu.Lock()
	raw, ok := s.keys[cacheKey]
	s.mu.Unlock()
	if !ok {
		var err error
		raw, err = pbkdf2.Key(sha256.New, p.password(s.secret, userID), []byte(p.salt), pbkdf2Iterations, fernet.KeySize)
		if err != nil {
			return nil, fmt.Errorf("legacy: derive key: %w", err)
		}
		s.mu.Lock()
		s.keys[cacheKey] = raw
		s.mu.Unlock()
	}
	return fernet.NewKey(raw)
}

// decryptFernet decrypts a Fernet token for a purpose and user.
func (s *Source) decryptFernet(p fernetPurpose, userID int64, token []byte) ([]byte, error) {
	key, err := s.fernetKey(p, userID)
	if err != nil {
		return nil, err
	}
	plain, err := key.Decrypt(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecordDamaged, err)
	}
	return plain, nil
}

// pythonISOFormat renders t as Python's datetime.isoformat() does for a
// naive value: microseconds are printed with six digits, or omitted
// entirely when they are zero. Several secrets bind to this text (the
// account incarnation), so it must match byte for byte.
func pythonISOFormat(t time.Time) string {
	base := t.Format("2006-01-02T15:04:05")
	if micro := t.Nanosecond() / 1000; micro != 0 {
		return fmt.Sprintf("%s.%06d", base, micro)
	}
	return base
}

// incarnationOf returns the account incarnation of app/automation_store.py
// by the normative rule of the migration specification:
// datetime.fromisoformat(created_at).isoformat().
func incarnationOf(createdAt string) (string, error) {
	iso, err := pythonFromISOFormatToISO(createdAt)
	if err != nil {
		return "", fmt.Errorf("legacy: unsupported timestamp %q", createdAt)
	}
	return iso, nil
}
