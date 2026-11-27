// Package principal says who is acting: the signed-in user and the browser
// session a request or realtime message belongs to. The transports
// (internal/httpapi, internal/realtime) put a Principal into the request
// context after validating the session; capabilities read it from there
// and never parse cookies or tokens themselves.
//
// The package also holds the shared vocabulary that the session, step-up
// and realtime contracts need on both sides of a package boundary:
// session revocations and the step-up action catalog. It imports only the
// standard library and internal/fault.
package principal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Principal is the authenticated actor of one request or one realtime
// connection. The zero value is not a valid principal.
type Principal struct {
	// UserID is the account's primary key. It is never reused.
	UserID int64
	// SessionID identifies the browser session (not the cookie token).
	// Revoking it ends every request and realtime connection that carries
	// it.
	SessionID string
	// Username is for display and audit only; authorization uses UserID.
	Username string
	// IsAdmin is the administrator flag at the time the session was
	// validated, including accounts listed in ADMIN_USERS.
	IsAdmin bool
	// Recovery marks a session opened with a recovery code. It may only
	// repair second factors (C-MFA-09); Require rejects it everywhere else.
	Recovery bool
	// Secure says the request or realtime connection reached the server
	// over HTTPS (request_reached_over_https); saved passwords need it.
	// The realtime endpoint sets it from the upgrade request.
	Secure bool
}

// Valid reports whether p names a user and a session.
func (p Principal) Valid() bool {
	return p.UserID > 0 && p.SessionID != ""
}

type contextKey struct{}

// With returns a context that carries p.
func With(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// From returns the principal of ctx. ok is false when ctx carries none or
// an invalid one.
func From(ctx context.Context) (p Principal, ok bool) {
	p, ok = ctx.Value(contextKey{}).(Principal)
	return p, ok && p.Valid()
}

// Require returns the principal of ctx for an ordinary action. It fails
// closed: no principal is AuthenticationNeeded, a recovery session is
// Forbidden.
func Require(ctx context.Context) (Principal, error) {
	p, err := RequireAllowingRecovery(ctx)
	if err != nil {
		return Principal{}, err
	}
	if p.Recovery {
		return Principal{}, fault.New(fault.Forbidden, "A recovery sign-in can only repair second factors.")
	}
	return p, nil
}

// RequireAllowingRecovery returns the principal of ctx and accepts a
// recovery session. Only the factor-repair actions use it.
func RequireAllowingRecovery(ctx context.Context) (Principal, error) {
	p, ok := From(ctx)
	if !ok {
		return Principal{}, fault.New(fault.AuthenticationNeeded, "")
	}
	return p, nil
}

// RequireAdmin returns the principal of ctx if it is an administrator in
// an ordinary session.
func RequireAdmin(ctx context.Context) (Principal, error) {
	p, err := Require(ctx)
	if err != nil {
		return Principal{}, err
	}
	if !p.IsAdmin {
		return Principal{}, fault.New(fault.Forbidden, "")
	}
	return p, nil
}
