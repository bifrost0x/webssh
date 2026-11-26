package main

import (
	"context"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
)

// gatedSession is the session service as the HTTP edge and the realtime
// endpoint use it: a valid session also passes the session gate of the
// build (the LDAP checks before every request of the Python release).
type gatedSession struct {
	*session.Service
	gate func(ctx context.Context, p principal.Principal) error
}

// Authenticate implements httpapi.SessionValidator and the realtime
// session validator.
func (g gatedSession) Authenticate(ctx context.Context, token string) (principal.Principal, error) {
	p, err := g.Service.Authenticate(ctx, token)
	if err != nil {
		return p, err
	}
	if err := g.gate(ctx, p); err != nil {
		return principal.Principal{}, err
	}
	return p, nil
}

// gatedSessions returns the session service with the gate, or the plain
// service when the build has none.
func (s *system) gatedSessions() interface {
	Authenticate(ctx context.Context, token string) (principal.Principal, error)
	Check(ctx context.Context, p principal.Principal) error
} {
	if s.optional.sessionGate == nil {
		return s.sessions
	}
	return gatedSession{Service: s.sessions, gate: s.optional.sessionGate}
}
