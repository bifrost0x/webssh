// Package realtime is the native WebSocket endpoint (ADR 0005): origin and
// session check on every upgrade, connection limits, the connection
// lifecycle and one dispatcher for all control messages. Capabilities
// register their message types as protocol.Route values; terminal bytes use
// the binary fast path.
//
// This file is the contract with the capabilities that serve the endpoint.
// The interfaces are declared here, by the consumer, and satisfied by
// internal/session, internal/auth and internal/audit; cmd/webssh connects
// them.
package realtime

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
)

// SessionValidator binds connections to browser sessions.
type SessionValidator interface {
	// Authenticate validates the session token from the upgrade request's
	// cookie and returns its principal. Any error refuses the upgrade with
	// 401; a valid token of a recovery session is returned with
	// Principal.Recovery set and the endpoint refuses it as well.
	Authenticate(ctx context.Context, token string) (principal.Principal, error)
	// Check re-validates a principal before every message whose Spec has
	// Mutates set and on the periodic re-check. An error closes the
	// connection with protocol.CloseUnauthenticated.
	Check(ctx context.Context, p principal.Principal) error
}

// Revocations delivers session revocations as they happen.
//
// The provider calls fn once per ended session, after the change is
// committed and before the call that ended the session returns, so that
// "revoked" and "connection closing" are never observably apart (condition
// K6). fn must not block: the endpoint marks the connections of the session
// as revoked, cancels their contexts and closes them with
// protocol.CloseUnauthenticated from another goroutine.
//
// To close the window between Authenticate and the first delivery, the
// endpoint registers a connection under its session ID before it calls
// Check once more and only then sends hello; a revocation in between is
// therefore either delivered to the registered connection or seen by Check.
type Revocations interface {
	Subscribe(fn func(principal.Revocation)) (cancel func())
}

// Limiter is the in-process rate limit shared with HTTP (provided by
// internal/auth). key is a protocol.Spec.RateKey.
type Limiter interface {
	Allow(userID int64, key string) (ok bool, retryAfter time.Duration)
}

// Auditor records the outcome of every request whose Spec has Mutates set
// (provided by internal/audit). msgType is the message type; err is the
// handler's error, nil on success.
type Auditor interface {
	RealtimeCall(ctx context.Context, p principal.Principal, msgType string, err error)
}
