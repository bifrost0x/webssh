package terminal

import (
	"context"
	"io"
	"sync"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// The methods in this file serve the test hooks of the e2e build
// (internal/e2eseed: OutputFlow and FixtureSessions). Only that build
// registers routes that reach them.

// TypeOutputStream binds a synthetic output stream to a channel before
// its first frame, so the page can deliver it to the session of that name.
// It belongs to the reserved e2e namespace.
const TypeOutputStream = "e2e.output_stream"

// OutputStream is the payload of TypeOutputStream.
type OutputStream struct {
	Ch        uint32 `json:"ch"`
	SessionID string `json:"session_id"`
}

// fixtureChannelBase is the first channel of synthetic streams. Clients
// allocate channels below it, so the two never meet.
const fixtureChannelBase uint32 = 1 << 31

// maxStreams bounds synthetic streams per connection at a time,
// maxStreamChannels over the connection's lifetime.
const (
	maxStreams        = 64
	maxStreamChannels = 1 << 16
)

// Emit sends one output frame of a synthetic stream through the same
// ledger as real sessions; it blocks while flow control holds the stream
// back and fails when ctx ends or the stream was detached.
func (m *Manager) Emit(ctx context.Context, peer protocol.Peer, stream string, seq uint64, data []byte) error {
	a, err := m.stream(peer, stream)
	if err != nil {
		return err
	}
	if err := m.flow.acquire(ctx, a.credit, seq, len(data)); err != nil {
		return err
	}
	return peer.SendBinary(protocol.AppendFrame(make([]byte, 0, protocol.HeaderLen+len(data)),
		protocol.Frame{Kind: protocol.KindOutput, Channel: a.ch, Seq: seq, Data: data}))
}

// InFlight is the number of unacknowledged output frames of the peer.
func (m *Manager) InFlight(peer protocol.Peer) int { return m.flow.connFrames(peer.ID()) }

func (m *Manager) stream(peer protocol.Peer, name string) (*attachment, error) {
	ps := m.peer(peer)
	if ps == nil {
		return nil, errPeerGone
	}
	ps.mu.Lock()
	if a := ps.streams[name]; a != nil {
		ps.mu.Unlock()
		return a, nil
	}
	if ps.closed || len(ps.streams) >= maxStreams || ps.nextStream >= maxStreamChannels {
		ps.mu.Unlock()
		return nil, fault.New(fault.RateLimited, "")
	}
	ch := fixtureChannelBase + ps.nextStream
	ps.nextStream++
	a := &attachment{peer: peer, ch: ch, credit: m.flow.open(peer.ID(), peer.Principal().UserID)}
	ps.atts[ch] = a
	ps.streams[name] = a
	ps.mu.Unlock()
	if err := peer.SendEvent(TypeOutputStream, OutputStream{Ch: ch, SessionID: name}); err != nil {
		m.dropAttachment(a)
		return nil, errPeerGone
	}
	return a, nil
}

// fixtureOutput is the screen of a restored fixture session, as in
// tests/e2e/workspace_restore.py.
const fixtureOutput = "restore fixture ready\r\n$ "

// maxFixtureSessions bounds fixture sessions per owner.
const maxFixtureSessions = 12

// ReplaceFixtureSessions ends the owner's fixture sessions and creates
// count connected, restorable ones backed by an idle shell. They do not
// count against the session quota. Sessions that are not fixtures are
// never touched.
func (m *Manager) ReplaceFixtureSessions(_ context.Context, _ protocol.Peer, owner int64, count int) ([]string, error) {
	if owner <= 0 || count < 0 || count > maxFixtureSessions {
		return nil, fault.New(fault.InvalidValue, "")
	}
	for _, s := range m.sessionsOf(owner) {
		if s.fixture {
			s.terminate(reasonClosed, nil)
		}
	}
	ids := make([]string, 0, count)
	for range count {
		info := protocol.SessionInfo{Host: "reload-fixture.local", Port: 22, Username: "fixture",
			AuthType: protocol.AuthPassword, ReconnectRouteKnown: true}
		s := m.newSession(owner, newIdleShell(), info, nil)
		s.fixture = true
		s.seq = 1
		s.replay.add(chunk{seq: 1, data: []byte(fixtureOutput)})
		if err := m.register(s); err != nil {
			return ids, err
		}
		s.start(nil)
		ids = append(ids, s.id)
	}
	return ids, nil
}

// idleShell produces no output until it is closed; input is discarded.
type idleShell struct {
	once   sync.Once
	closed chan struct{}
}

func newIdleShell() *idleShell { return &idleShell{closed: make(chan struct{})} }

func (s *idleShell) Read([]byte) (int, error) {
	<-s.closed
	return 0, io.EOF
}

func (s *idleShell) Write(p []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}

func (s *idleShell) Resize(int, int) error { return nil }
func (s *idleShell) Wait() error           { <-s.closed; return nil }
func (s *idleShell) Close() error          { s.once.Do(func() { close(s.closed) }); return nil }
