package legacy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/bifrost0x/webssh/internal/otp"
)

// TOTPSecret is a decrypted TOTP secret of an authenticator or of a pending
// enrollment.
type TOTPSecret struct {
	ID       int64
	UserID   int64
	Label    string
	Active   bool          // false for enrollments and inactive authenticators
	LastStep sql.NullInt64 // last accepted time step (replay protection)
	Pending  bool          // true for a row of totp_enrollments
	Base32   string        // the secret as shown to the user
	Key      []byte        // the decoded secret
}

// TOTPSecrets decrypts every TOTP secret: totp_authenticators and the
// pending totp_enrollments. Each token is a Fernet token under the key of
// app/mfa_crypto.py.
func (s *Source) TOTPSecrets(ctx context.Context) ([]TOTPSecret, error) {
	if !s.schema.HasTable("totp_authenticators") && !s.schema.HasTable("totp_enrollments") {
		return nil, nil
	}
	if !s.schema.HasTable("totp_authenticators") || !s.schema.HasTable("totp_enrollments") {
		return nil, errors.New("legacy: only one of the TOTP tables exists")
	}
	const query = `SELECT id, user_id, label, active, last_accepted_step, encrypted_secret, 0 FROM totp_authenticators
		UNION ALL SELECT id, user_id, label, 0, NULL, encrypted_secret, 1 FROM totp_enrollments ORDER BY 7, 1`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("legacy: read TOTP secrets: %w", err)
	}
	defer rows.Close()
	var out []TOTPSecret
	for rows.Next() {
		var t TOTPSecret
		var token []byte
		if err := rows.Scan(&t.ID, &t.UserID, &t.Label, &t.Active, &t.LastStep, &token, &t.Pending); err != nil {
			return nil, fmt.Errorf("legacy: read TOTP secrets: %w", err)
		}
		plain, err := s.decryptFernet(totpPurpose, t.UserID, token)
		if err != nil {
			return nil, fmt.Errorf("legacy: TOTP secret %d of user %d: %w", t.ID, t.UserID, err)
		}
		t.Base32 = string(plain)
		if t.Key, err = otp.DecodeSecret(t.Base32); err != nil {
			return nil, fmt.Errorf("legacy: TOTP secret %d of user %d: %w", t.ID, t.UserID, err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RecoveryCodeHashes returns the stored recovery code hashes per user.
func (s *Source) RecoveryCodeHashes(ctx context.Context) (map[int64][][]byte, error) {
	if !s.schema.HasTable("recovery_codes") {
		return map[int64][][]byte{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, code_hash FROM recovery_codes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read recovery codes: %w", err)
	}
	defer rows.Close()
	out := map[int64][][]byte{}
	for rows.Next() {
		var userID int64
		var hash []byte
		if err := rows.Scan(&userID, &hash); err != nil {
			return nil, fmt.Errorf("legacy: read recovery codes: %w", err)
		}
		if len(hash) != sha256.Size {
			return nil, fmt.Errorf("legacy: recovery code of user %d has %d bytes", userID, len(hash))
		}
		out[userID] = append(out[userID], hash)
	}
	return out, rows.Err()
}

// RecoveryCodeHash hashes a recovery code as app/recovery_service.py does
// for the codes it generates (hex groups). It serves the migration's
// verification only: Python's str.upper() and str.split() treat some
// non-ASCII input differently (for example "\u00df" becomes "SS"), so the
// sign-in phase needs its own normalisation for user input.
//
// The hash is SHA-256 over a domain prefix and the upper-cased code without whitespace,
// with non-ASCII characters dropped.
func RecoveryCodeHash(code string) []byte {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r > unicode.MaxASCII {
			return -1
		}
		return r
	}, strings.ToUpper(code))
	sum := sha256.Sum256(append([]byte("webssh-recovery-code-v1\x00"), normalized...))
	return sum[:]
}

// MatchRecoveryCode reports whether code matches one of hashes.
func MatchRecoveryCode(hashes [][]byte, code string) bool {
	want := RecoveryCodeHash(code)
	found := 0
	for _, h := range hashes {
		found |= subtle.ConstantTimeCompare(h, want)
	}
	return found == 1
}

// GitHubConfiguration is the GitHub sign-in configuration with its client
// secret decrypted.
type GitHubConfiguration struct {
	Enabled       bool
	ClientID      string
	ClientSecret  string // empty when none is stored
	RedirectURI   string
	AutoProvision bool
	AllowedOrgs   string // JSON array text as stored
	Generation    int64
}

// GitHubConfiguration reads the single configuration row, if any.
func (s *Source) GitHubConfiguration(ctx context.Context) (*GitHubConfiguration, error) {
	if !s.schema.HasTable("github_auth_configuration") {
		return nil, nil
	}
	var c GitHubConfiguration
	var token []byte
	err := s.db.QueryRowContext(ctx, `SELECT enabled, client_id, encrypted_client_secret, redirect_uri,
		auto_provision, allowed_orgs_json, generation FROM github_auth_configuration ORDER BY id LIMIT 1`).
		Scan(&c.Enabled, &c.ClientID, &token, &c.RedirectURI, &c.AutoProvision, &c.AllowedOrgs, &c.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("legacy: read GitHub configuration: %w", err)
	}
	if len(token) > 0 {
		plain, err := s.decryptFernet(githubPurpose, 0, token)
		if err != nil {
			return nil, fmt.Errorf("legacy: GitHub client secret: %w", err)
		}
		c.ClientSecret = string(plain)
	}
	return &c, nil
}
