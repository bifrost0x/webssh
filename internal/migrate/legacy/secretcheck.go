package legacy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// SecretCheck names the record that proved SECRET_KEY (A02).
type SecretCheck struct {
	Checked bool   // false: the legacy data holds no encrypted record
	Entity  string // entity of the record decrypted, or that failed
	UserID  int64
}

// CheckSecret decrypts existing secrets with SECRET_KEY before the
// migration writes anything (migration specification A02): the TOTP
// authenticators, the GitHub client secret, then the SSH keys and saved
// passwords of each account. SECRET_KEY is proven by the first record
// that decrypts; a record that does not is then a damaged record, which
// the read of its step reports with entity, user and record
// (ErrRecordDamaged, specification 8.3). Only when no record decrypts is
// the result ErrSecretMismatch, naming the first record that failed. With
// no encrypted data the check cannot run; Checked is false and the report
// says so.
func (s *Source) CheckSecret(ctx context.Context) (SecretCheck, error) {
	var failed SecretCheck
	var failure error
	fail := func(c SecretCheck, err error) {
		if failure == nil {
			failed, failure = c, err
		}
	}
	if ok, user, err := s.anyTOTPDecrypts(ctx); ok {
		return SecretCheck{Checked: true, Entity: "E08", UserID: user}, nil
	} else if err != nil {
		fail(SecretCheck{Entity: "E08", UserID: user}, err)
	}
	gh, err := s.GitHubConfiguration(ctx)
	switch {
	case err != nil:
		fail(SecretCheck{Entity: "E06"}, err)
	case gh != nil && gh.ClientSecret != "":
		return SecretCheck{Checked: true, Entity: "E06"}, nil
	}
	dirs, err := s.UserDirectories()
	if err != nil {
		return SecretCheck{}, err
	}
	for _, dir := range dirs {
		id, err := strconv.ParseInt(strings.TrimPrefix(dir, "user_"), 10, 64)
		if err != nil || !strings.HasPrefix(dir, "user_") {
			continue
		}
		if keys, err := s.SSHKeys(id); err != nil {
			fail(SecretCheck{Entity: "E23", UserID: id}, err)
		} else {
			for _, k := range keys.Keys {
				if !k.PlaintextAtRest {
					return SecretCheck{Checked: true, Entity: "E23", UserID: id}, nil
				}
			}
		}
		if creds, _, err := s.NamedCredentials(ctx, id); err != nil {
			fail(SecretCheck{Entity: "E32", UserID: id}, err)
		} else if len(creds) > 0 {
			return SecretCheck{Checked: true, Entity: "E32", UserID: id}, nil
		}
	}
	if failure != nil {
		return failed, fmt.Errorf("%w: %w", ErrSecretMismatch, failure)
	}
	return SecretCheck{}, nil
}

// anyTOTPDecrypts reports whether one TOTP authenticator decrypts, with
// its user; otherwise the first failure and its user.
func (s *Source) anyTOTPDecrypts(ctx context.Context) (bool, int64, error) {
	if !s.schema.HasTable("totp_authenticators") {
		return false, 0, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, encrypted_secret FROM totp_authenticators ORDER BY id`)
	if err != nil {
		return false, 0, fmt.Errorf("legacy: read TOTP secrets: %w", err)
	}
	defer rows.Close()
	var first error
	var firstUser int64
	for rows.Next() {
		var t TOTPSecret
		var token []byte
		if err := rows.Scan(&t.ID, &t.UserID, &token); err != nil {
			return false, 0, fmt.Errorf("legacy: read TOTP secrets: %w", err)
		}
		if _, err := s.decryptFernet(totpPurpose, t.UserID, token); err != nil {
			if first == nil {
				first, firstUser = totpError(t, err), t.UserID
			}
			continue
		}
		return true, t.UserID, nil
	}
	if err := rows.Err(); err != nil {
		return false, 0, fmt.Errorf("legacy: read TOTP secrets: %w", err)
	}
	return false, firstUser, first
}
