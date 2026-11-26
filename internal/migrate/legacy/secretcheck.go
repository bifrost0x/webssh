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
// passwords of the first account that has any. A failure is
// ErrSecretMismatch, with the entity and user that did not decrypt. With
// no encrypted data the check cannot run; Checked is false and the report
// says so.
func (s *Source) CheckSecret(ctx context.Context) (SecretCheck, error) {
	totp, err := s.TOTPAuthenticators(ctx)
	if err != nil {
		return SecretCheck{Entity: "E08"}, fmt.Errorf("%w: %w", ErrSecretMismatch, err)
	}
	if len(totp) > 0 {
		return SecretCheck{Checked: true, Entity: "E08", UserID: totp[0].UserID}, nil
	}
	gh, err := s.GitHubConfiguration(ctx)
	if err != nil {
		return SecretCheck{Entity: "E06"}, fmt.Errorf("%w: %w", ErrSecretMismatch, err)
	}
	if gh != nil && gh.ClientSecret != "" {
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
		keys, err := s.SSHKeys(id)
		if err != nil {
			return SecretCheck{Entity: "E23", UserID: id}, fmt.Errorf("%w: %w", ErrSecretMismatch, err)
		}
		for _, k := range keys.Keys {
			if !k.PlaintextAtRest {
				return SecretCheck{Checked: true, Entity: "E23", UserID: id}, nil
			}
		}
		creds, _, err := s.NamedCredentials(ctx, id)
		if err != nil {
			return SecretCheck{Entity: "E32", UserID: id}, fmt.Errorf("%w: %w", ErrSecretMismatch, err)
		}
		if len(creds) > 0 {
			return SecretCheck{Checked: true, Entity: "E32", UserID: id}, nil
		}
	}
	return SecretCheck{}, nil
}
