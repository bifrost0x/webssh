package terminal

import (
	"errors"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// queueRetry is the retry hint when the input queue towards the shell is
// full.
const queueRetry = 50 * time.Millisecond

var errFrameKind = errors.New("terminal: unexpected binary frame kind")

// maxDroppedFrames is how many input and acknowledgement frames in a row a
// connection may send that are dropped unread (unknown channel, a
// sequence other than the expected one) before it is closed with 4002.
// Go-Back-N drops at most the frames in flight after a refusal, and a
// late frame after a detach is a handful; a client that keeps sending
// into the void only costs the server work.
const maxDroppedFrames = 1024

var errDroppedFrames = errors.New("terminal: too many dropped frames")

// HandleBinary is the fast path for input and acknowledgement frames
// (realtime.BinaryHandler). It runs on the connection's read loop and
// never blocks. An error closes the connection with 4002: a frame that is
// malformed, larger than SSH_INPUT_MAX_BYTES or of the output kind, and
// a run of more than maxDroppedFrames dropped frames.
func (m *Manager) HandleBinary(p protocol.Peer, data []byte) error {
	f, err := protocol.DecodeFrame(data, m.cfg.Input.MaxFrameBytes)
	if err != nil {
		return err
	}
	if f.Kind == protocol.KindOutput {
		return errFrameKind
	}
	// A frame read just before a revocation may still arrive here; the
	// peer context has ended by then and nothing is forwarded (K6).
	if p.Context().Err() != nil {
		return nil
	}
	a := m.attachmentOf(p, f.Channel)
	if a == nil || f.Kind == protocol.KindInput && (a.sess == nil || f.Seq != a.nextISeq) {
		// The stream is gone or the frame is out of order: dropped.
		return m.dropped(p)
	}
	m.resetDropped(p)
	switch f.Kind {
	case protocol.KindAck:
		m.flow.ack(a.credit, f.Seq)
	case protocol.KindInput:
		m.input1(p, a, f)
	}
	return nil
}

// dropped counts a dropped frame of p and fails once the connection
// dropped maxDroppedFrames in a row (R1/R2 I-2).
func (m *Manager) dropped(p protocol.Peer) error {
	ps := m.peer(p)
	if ps == nil {
		return nil
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.dropped++
	if ps.dropped > maxDroppedFrames {
		return errDroppedFrames
	}
	return nil
}

func (m *Manager) resetDropped(p protocol.Peer) {
	m.mu.Lock()
	ps := m.peers[p.ID()]
	m.mu.Unlock()
	if ps == nil {
		return
	}
	ps.mu.Lock()
	ps.dropped = 0
	ps.mu.Unlock()
}

// input1 applies Go-Back-N to the frame with the expected sequence (any
// other is dropped in HandleBinary). A refusal of the expected frame sends
// one terminal.input_rejected, and the frames after it are dropped until
// the client sends that sequence again, so input never reorders and
// keystrokes need no acknowledgement each.
func (m *Manager) input1(p protocol.Peer, a *attachment, f protocol.Frame) {
	s := a.sess
	now := m.now()
	ok, wait := m.input.allow(s.owner, s.id, len(f.Data), now)
	if ok {
		if b := filterInput(f.Data); len(b) > 0 {
			// Data aliases the read buffer of the connection.
			if !s.enqueueInput(append([]byte(nil), b...), now) {
				ok, wait = false, queueRetry
			}
		}
	}
	if !ok {
		_ = p.SendEvent(protocol.TypeTerminalInputReject, protocol.TerminalInputRejected{
			Ch: a.ch, ISeq: f.Seq, Code: fault.InputBackpressure, RetryAfterMS: max(wait.Milliseconds(), 1),
		})
		return
	}
	a.nextISeq++
	if f.Flags&protocol.FlagWantAck != 0 {
		_ = p.SendEvent(protocol.TypeTerminalInputAck, protocol.TerminalInputAck{Ch: a.ch, ISeq: f.Seq})
	}
}
