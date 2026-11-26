// Package protocoltest provides a fake realtime connection for testing
// capability handlers without the WebSocket edge. Only test files import it
// (architecture tests).
package protocoltest

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// ErrClosed is returned by sends after Close, like the real connection.
var ErrClosed = errors.New("protocoltest: connection closed")

var nextID atomic.Uint64

// Event is one server event a handler sent.
type Event struct {
	Type    string
	Payload jsontext.Value
}

// Peer is a protocol.Peer that records what handlers send. Events pass
// through protocol.EncodeEnvelope, so a payload that is not a JSON object
// fails the test as it would fail on the wire.
type Peer struct {
	t      testing.TB
	id     uint64
	p      principal.Principal
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	events []Event
	frames [][]byte
}

var _ protocol.Peer = (*Peer)(nil)

// NewPeer returns an open connection of p. It is closed when the test ends.
func NewPeer(t testing.TB, p principal.Principal) *Peer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Peer{t: t, id: nextID.Add(1), p: p, ctx: ctx, cancel: cancel}
}

// ID implements protocol.Peer.
func (p *Peer) ID() uint64 { return p.id }

// Principal implements protocol.Peer.
func (p *Peer) Principal() principal.Principal { return p.p }

// Context implements protocol.Peer.
func (p *Peer) Context() context.Context { return p.ctx }

// Close ends the connection, as a revocation or disconnect would.
func (p *Peer) Close() { p.cancel() }

// SendEvent implements protocol.Peer.
func (p *Peer) SendEvent(typ string, payload any) error {
	if p.ctx.Err() != nil {
		return ErrClosed
	}
	raw, err := protocol.EncodeEnvelope(typ, "", payload)
	if err != nil {
		p.t.Errorf("SendEvent(%q): %v", typ, err)
		return err
	}
	env, err := protocol.DecodeEnvelope(raw)
	if err != nil {
		p.t.Errorf("SendEvent(%q) produced an invalid envelope: %v", typ, err)
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, Event{Type: typ, Payload: env.P})
	return nil
}

// SendBinary implements protocol.Peer.
func (p *Peer) SendBinary(frame []byte) error {
	if p.ctx.Err() != nil {
		return ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.frames = append(p.frames, append([]byte(nil), frame...))
	return nil
}

// Events returns the events sent so far, optionally only those of types.
func (p *Peer) Events(types ...string) []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Event
	for _, e := range p.events {
		if len(types) == 0 || slices.Contains(types, e.Type) {
			out = append(out, e)
		}
	}
	return out
}

// Frames returns the binary frames sent so far.
func (p *Peer) Frames() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]byte(nil), p.frames...)
}

// Call runs route for peer as the dispatcher does: the payload is encoded,
// checked against the route's MaxPayload, decoded strictly and validated;
// errors come back in wire form. It does not re-validate sessions or apply
// rate limits; those belong to the edge.
func Call(ctx context.Context, route protocol.Route, peer protocol.Peer, payload any) (jsontext.Value, *protocol.Error) {
	var raw jsontext.Value
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, protocol.WireError(err)
		}
		raw = b
	}
	limit := route.Spec.MaxPayload
	if limit <= 0 {
		limit = protocol.DefaultMaxPayload
	}
	if len(raw) > limit {
		return nil, protocol.WireError(fault.New(fault.TooLarge, ""))
	}
	resp, err := route.Run(ctx, peer, raw)
	if err != nil {
		return nil, protocol.WireError(err)
	}
	if resp == nil {
		return nil, nil
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, protocol.WireError(err)
	}
	return b, nil
}
