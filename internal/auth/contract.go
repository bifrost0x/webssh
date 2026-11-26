// Package auth runs the sign-in flow: provider and factor registries,
// assurance, recovery, in-process rate limits and the one way to turn off a
// second factor. Providers (internal/auth/local, later LDAP, OIDC, GitHub)
// and factors (internal/auth/totp, internal/auth/webauthn) implement the
// interfaces below and are registered in cmd/webssh.
package auth

import (
	"context"
	"encoding/json/jsontext"
)

// Provider checks a primary credential. Authenticate fails with
// fault.AuthFailed for every wrong combination of name and secret,
// including unknown and locked accounts, with the same timing; the flow
// shows one message for all of them.
type Provider interface {
	Name() string
	Authenticate(ctx context.Context, username, secret string) (userID int64, err error)
}

// Factor is a second factor. Verify checks the factor-specific response
// (TOTP code, WebAuthn assertion) and fails with fault.AuthFailed or
// fault.RateLimited; replay protection is the factor's job.
type Factor interface {
	Kind() string
	Enrolled(ctx context.Context, userID int64) (bool, error)
	Verify(ctx context.Context, userID int64, response jsontext.Value) error
}
