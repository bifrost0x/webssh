package gateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// DefaultMaxAttempts bounds the attempts waiting for the browser, process
// wide.
const DefaultMaxAttempts = 64

// recheckInterval is how often a running gateway attempt reads the switch.
const recheckInterval = time.Second

var (
	errBusy     = fault.New(fault.Busy, "Connection request already in progress")
	errFull     = fault.New(fault.Busy, "SSH connection limit reached or request unavailable")
	errNoPrompt = fault.New(fault.NotFound, "The prompt is no longer open.")
)

type attemptKey struct {
	peer      uint64
	requestID string
}

type entry struct {
	attempt *Attempt
	cancel  context.CancelCauseFunc
	gateway bool
}

// Registry holds the attempts that wait for the browser and answers the
// area's client requests (prompt.respond, gateway.input, gateway.ack).
// An attempt is found by the connection and request_id that started it;
// every mismatch of connection, user or prompt looks like a missing
// prompt.
type Registry struct {
	// Enabled reads the administrator switch ssh_gateway_enabled. It is
	// asked before and during every gateway attempt; nil means enabled.
	Enabled func(ctx context.Context) bool
	// Max bounds the attempts held at once (default DefaultMaxAttempts).
	Max int
	// Now replaces the clock in tests.
	Now func() time.Time

	mu       sync.Mutex
	attempts map[attemptKey]*entry
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Registry) enabled(ctx context.Context) bool {
	return r.Enabled == nil || r.Enabled(ctx)
}

// Begin registers an attempt of owner for requestID on the connection
// events belongs to. gateway marks an attempt through an SSH gateway: it
// needs the administrator switch and ends with ErrDisabled when the switch
// goes off. The returned context ends with ctx, after AttemptTimeout, or
// when the attempt is cancelled; end removes the attempt and must be
// called once it is over.
func (r *Registry) Begin(ctx context.Context, owner Owner, requestID string, events Events, gateway bool) (*Attempt, context.Context, func(), error) {
	if gateway && !r.enabled(ctx) {
		return nil, nil, nil, ErrDisabled
	}
	k := attemptKey{peer: owner.Peer, requestID: requestID}
	actx, cancelTimeout := context.WithTimeout(ctx, AttemptTimeout)
	actx, cancel := context.WithCancelCause(actx)
	var check func() error
	if gateway {
		check = r.switchCheck(actx)
	}
	a := newAttempt(owner, requestID, events, check, r.now())
	e := &entry{attempt: a, cancel: cancel, gateway: gateway}

	r.mu.Lock()
	limit := r.Max
	if limit <= 0 {
		limit = DefaultMaxAttempts
	}
	switch {
	case r.attempts[k] != nil:
		r.mu.Unlock()
		cancel(nil)
		cancelTimeout()
		return nil, nil, nil, errBusy
	case len(r.attempts) >= limit:
		r.mu.Unlock()
		cancel(nil)
		cancelTimeout()
		return nil, nil, nil, errFull
	}
	if r.attempts == nil {
		r.attempts = map[attemptKey]*entry{}
	}
	r.attempts[k] = e
	r.mu.Unlock()

	end := func() {
		r.mu.Lock()
		if r.attempts[k] == e {
			delete(r.attempts, k)
		}
		r.mu.Unlock()
		cancel(nil)
		cancelTimeout()
	}
	return a, actx, end, nil
}

// switchCheck reports ErrDisabled once the attempt was cancelled by Disable
// or the switch reads off. The switch is read at most once per
// recheckInterval, so a stream of output frames does not read the setting
// for each frame; Disable takes effect at once.
func (r *Registry) switchCheck(ctx context.Context) func() error {
	var mu sync.Mutex
	var last time.Time
	return func() error {
		if errors.Is(context.Cause(ctx), ErrDisabled) {
			return ErrDisabled
		}
		mu.Lock()
		defer mu.Unlock()
		if now := r.now(); last.IsZero() || now.Sub(last) >= recheckInterval {
			last = now
			if !r.enabled(ctx) {
				return ErrDisabled
			}
		}
		return nil
	}
}

// Disable cancels every pending gateway attempt; the administrator
// switched the gateway off. Attempts that do not use the gateway go on.
func (r *Registry) Disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.attempts {
		if e.gateway {
			e.cancel(ErrDisabled)
		}
	}
}

// Pending reports the number of attempts held (for tests and status).
func (r *Registry) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attempts)
}

func (r *Registry) find(ctx context.Context, peer protocol.Peer, requestID string) (*Attempt, Owner, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, Owner{}, err
	}
	r.mu.Lock()
	e := r.attempts[attemptKey{peer: peer.ID(), requestID: requestID}]
	r.mu.Unlock()
	owner := Owner{Peer: peer.ID(), UserID: p.UserID}
	if e == nil || e.attempt.owner != owner {
		return nil, owner, errNoPrompt
	}
	return e.attempt, owner, nil
}

// Routes are the client requests of the area "gateway". They only hand
// values to a waiting attempt and run inline on the read loop.
func (r *Registry) Routes() []protocol.Route {
	return []protocol.Route{
		protocol.Handle(protocol.TypePromptRespond, protocol.Spec{MaxPayload: protocol.PromptRespondMaxPayload}, r.respond),
		protocol.Handle(protocol.TypeGatewayInput, protocol.Spec{MaxPayload: protocol.GatewayInputMaxPayload}, r.input),
		protocol.Handle(protocol.TypeGatewayAck, protocol.Spec{}, r.ack),
	}
}

func (r *Registry) respond(ctx context.Context, peer protocol.Peer, req protocol.PromptRespond) (*protocol.Empty, error) {
	a, owner, err := r.find(ctx, peer, req.RequestID)
	if err != nil {
		return nil, err
	}
	if !a.Answer(owner, req.PromptID, req.Answers) {
		return nil, errNoPrompt
	}
	return nil, nil
}

func (r *Registry) input(ctx context.Context, peer protocol.Peer, req protocol.GatewayInput) (*protocol.Empty, error) {
	a, owner, err := r.find(ctx, peer, req.RequestID)
	if err != nil {
		return nil, err
	}
	if !a.Input(owner, req.Data) {
		return nil, fault.New(fault.InvalidRequest, "The gateway terminal does not accept this input.")
	}
	return nil, nil
}

func (r *Registry) ack(ctx context.Context, peer protocol.Peer, req protocol.GatewayAck) (*protocol.Empty, error) {
	a, owner, err := r.find(ctx, peer, req.RequestID)
	if err != nil {
		return nil, err
	}
	if !a.Ack(owner, req.Sequence) {
		return nil, errNoPrompt
	}
	return nil, nil
}
