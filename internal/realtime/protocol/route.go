package protocol

import (
	"context"
	"encoding/json/jsontext"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Peer is the view a capability has of one realtime connection.
type Peer interface {
	// ID is unique per process lifetime; capabilities key state on it.
	ID() uint64
	// Principal is the authenticated owner, fixed for the connection's
	// lifetime. It is also in the handler's context (principal.From).
	Principal() principal.Principal
	// Context ends when the connection ends, at the latest when its
	// session is revoked. Work started for the peer must stop with it.
	Context() context.Context
	// SendEvent pushes a server event; it never blocks. An error means the
	// connection is gone or was closed for not keeping up.
	SendEvent(typ string, payload any) error
	// SendBinary pushes an encoded binary frame; it never blocks.
	SendBinary(frame []byte) error
}

// Spec is the contract of one message type. The dispatcher enforces it, so
// handlers contain only capability logic: no payload checks, no session
// re-checks, no error envelopes, no audit calls.
type Spec struct {
	// MaxPayload bounds the raw JSON payload in bytes (default
	// DefaultMaxPayload).
	MaxPayload int
	// Async runs the handler in its own goroutine, bounded per connection,
	// for work that waits on the network. Inline handlers run in order on
	// the read loop and must be fast.
	Async bool
	// Timeout bounds the handler (default DefaultTimeout).
	Timeout time.Duration
	// Mutates re-validates the browser session immediately before the
	// handler runs and sends the outcome to the audit hook. A failed
	// re-validation closes the connection with CloseUnauthenticated and the
	// handler does not run.
	Mutates bool
	// RateKey groups types into one rate-limit bucket ("" = none).
	RateKey string
	// RateMessage is the message of a refusal by the rate limit ("" = the
	// default of fault.RateLimited), for the areas whose Python handler
	// had its own text.
	RateMessage string
}

// Defaults the dispatcher applies to a zero Spec field.
const (
	DefaultMaxPayload = 4 << 10
	DefaultTimeout    = 30 * time.Second
)

// Route binds a message type to a handler. Build it with Handle.
type Route struct {
	Type string
	Spec Spec
	Run  func(ctx context.Context, peer Peer, p jsontext.Value) (any, error)
}

// Validator is implemented by request types with rules beyond JSON shape.
// Validate may normalize the request (clamp sizes); its error text is sent
// to the client and must be safe to show.
type Validator interface{ Validate() error }

// Handle builds a typed route: the payload is decoded strictly into Req and
// validated before h runs. The handler's context carries the peer's
// principal.
func Handle[Req, Resp any](typ string, spec Spec, h func(ctx context.Context, peer Peer, req Req) (Resp, error)) Route {
	return Route{Type: typ, Spec: spec, Run: func(ctx context.Context, peer Peer, p jsontext.Value) (any, error) {
		var req Req
		if err := DecodePayload(p, &req); err != nil {
			return nil, fault.Wrap(fault.InvalidRequest, err, "invalid payload")
		}
		if v, ok := any(&req).(Validator); ok {
			if err := v.Validate(); err != nil {
				if _, classified := fault.From(err); classified {
					return nil, err
				}
				return nil, fault.Wrap(fault.InvalidRequest, err, err.Error())
			}
		}
		return h(principal.With(ctx, peer.Principal()), peer, req)
	}}
}

// Empty is the request or response type of messages without a payload.
type Empty struct{}
