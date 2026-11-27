package terminal

import (
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// attachment is one terminal stream of one connection: a session bound to
// a client-allocated channel. Synthetic streams of the e2e output load
// have no session.
type attachment struct {
	sess   *Session
	peer   protocol.Peer
	ch     uint32
	credit *credit

	// Input state, touched only from the connection's read loop.
	nextISeq uint64
}

// peerState holds the channels of one connection.
type peerState struct {
	mu       sync.Mutex
	atts     map[uint32]*attachment
	reserved map[uint32]bool // channels of terminal.open still connecting
	streams  map[string]*attachment
	// cooldown holds, per session, until when a stream detached for
	// backpressure may not attach again.
	cooldown map[string]time.Time
	closed   bool
	// dropped counts frames dropped in a row (HandleBinary).
	dropped int
}

// peer returns the state of a live connection, nil for a closed one.
func (m *Manager) peer(p protocol.Peer) *peerState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.Context().Err() != nil {
		return nil
	}
	ps := m.peers[p.ID()]
	if ps == nil {
		ps = &peerState{atts: map[uint32]*attachment{}, reserved: map[uint32]bool{}, streams: map[string]*attachment{}, cooldown: map[string]time.Time{}}
		m.peers[p.ID()] = ps
	}
	return ps
}

var errPeerGone = fault.New(fault.Cancelled, "")

// reattachCooldown delays a new attachment of a connection to a session
// whose stream on it was detached for backpressure, so a client that does
// not read cannot keep taking the shared output budget of others. The
// page retries after retry_after_ms.
const reattachCooldown = time.Second

func (m *Manager) attachmentOf(p protocol.Peer, ch uint32) *attachment {
	m.mu.Lock()
	ps := m.peers[p.ID()]
	m.mu.Unlock()
	if ps == nil {
		return nil
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.atts[ch]
}

func (m *Manager) allAttachments() []*attachment {
	m.mu.Lock()
	peers := make([]*peerState, 0, len(m.peers))
	for _, ps := range m.peers {
		peers = append(peers, ps)
	}
	m.mu.Unlock()
	var out []*attachment
	for _, ps := range peers {
		ps.mu.Lock()
		for _, a := range ps.atts {
			out = append(out, a)
		}
		ps.mu.Unlock()
	}
	return out
}

// claim takes channel ch of the connection, for terminal.open while it
// connects or for an attachment.
func (ps *peerState) claimLocked(ch uint32, limit int) error {
	switch {
	case ps.closed:
		return errPeerGone
	case ps.atts[ch] != nil || ps.reserved[ch]:
		return fault.New(fault.ChannelInUse, "")
	case len(ps.atts)+len(ps.reserved) >= limit:
		return fault.New(fault.RateLimited, "Too many terminals on this connection.")
	}
	return nil
}

// reserve claims ch for a connection attempt; release frees it unless the
// attempt bound it.
func (m *Manager) reserve(p protocol.Peer, ch uint32) (release func(), err error) {
	ps := m.peer(p)
	if ps == nil {
		return nil, errPeerGone
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if err := ps.claimLocked(ch, m.cfg.MaxChannels); err != nil {
		return nil, err
	}
	ps.reserved[ch] = true
	return func() {
		ps.mu.Lock()
		delete(ps.reserved, ch)
		ps.mu.Unlock()
	}, nil
}

// attach binds session s to channel ch of p and replays its output after
// afterSeq, all before it returns, so the replay precedes the result.
// Snapshot and registration happen under the session lock: no live chunk
// is lost or sent twice. reserved says ch was claimed by reserve.
func (m *Manager) attach(p protocol.Peer, s *Session, ch uint32, afterSeq uint64, reserved bool) (protocol.TerminalAttached, error) {
	ps := m.peer(p)
	if ps == nil {
		return protocol.TerminalAttached{}, errPeerGone
	}
	ps.mu.Lock()
	if until, ok := ps.cooldown[s.id]; ok {
		if wait := until.Sub(m.now()); wait > 0 {
			ps.mu.Unlock()
			e := fault.New(fault.Backpressure, "Acknowledge pending output first.")
			e.RetryAfter = wait
			return protocol.TerminalAttached{}, e
		}
		delete(ps.cooldown, s.id)
	}
	if !reserved || !ps.reserved[ch] {
		if err := ps.claimLocked(ch, m.cfg.MaxChannels); err != nil {
			ps.mu.Unlock()
			return protocol.TerminalAttached{}, err
		}
	}
	if ps.closed {
		ps.mu.Unlock()
		return protocol.TerminalAttached{}, errPeerGone
	}
	delete(ps.reserved, ch)
	a := &attachment{sess: s, peer: p, ch: ch, credit: m.flow.open(p.ID(), s.owner), nextISeq: 1}
	ps.atts[ch] = a
	ps.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		m.dropAttachment(a)
		return protocol.TerminalAttached{}, fault.New(fault.NotFound, "Session not found.")
	}
	chunks, full := s.replay.since(afterSeq)
	frames, cut, ok := m.flow.reserveReplay(a.credit, coalesce(chunks, m.cfg.ReadSize))
	if !ok {
		m.dropAttachment(a)
		e := fault.New(fault.Backpressure, "Acknowledge pending output first.")
		e.RetryAfter = 500 * time.Millisecond
		return protocol.TerminalAttached{}, e
	}
	full = full || cut
	for i, f := range frames {
		flags := protocol.FlagReplay
		if i == 0 && full {
			flags |= protocol.FlagReset
		}
		frame := protocol.AppendFrame(make([]byte, 0, protocol.HeaderLen+len(f.data)),
			protocol.Frame{Kind: protocol.KindOutput, Flags: flags, Channel: ch, Seq: f.seq, Data: f.data})
		if err := p.SendBinary(frame); err != nil {
			m.dropAttachment(a)
			return protocol.TerminalAttached{}, errPeerGone
		}
	}
	s.attached[a] = struct{}{}
	return protocol.TerminalAttached{Ch: ch, SessionID: s.id, Seq: s.seq, Full: full}, nil
}

// dropAttachment releases the stream's credit and frees its channel.
func (m *Manager) dropAttachment(a *attachment) {
	m.flow.close(a.credit)
	m.mu.Lock()
	ps := m.peers[a.peer.ID()]
	m.mu.Unlock()
	if ps == nil {
		return
	}
	ps.mu.Lock()
	if ps.atts[a.ch] == a {
		delete(ps.atts, a.ch)
	}
	for name, st := range ps.streams {
		if st == a {
			delete(ps.streams, name)
		}
	}
	ps.mu.Unlock()
}

// detach removes an attachment. A non-empty reason tells the browser to
// attach again (terminal.resync_required); the session keeps running.
func (m *Manager) detach(a *attachment, reason string) {
	was := false
	if s := a.sess; s != nil {
		s.mu.Lock()
		_, was = s.attached[a]
		delete(s.attached, a)
		s.mu.Unlock()
	}
	m.dropAttachment(a)
	if was && reason == reasonBackpressure {
		m.mu.Lock()
		ps := m.peers[a.peer.ID()]
		m.mu.Unlock()
		if ps != nil {
			ps.mu.Lock()
			ps.cooldown[a.sess.id] = m.now().Add(reattachCooldown)
			ps.mu.Unlock()
		}
	}
	if was && reason != "" {
		_ = a.peer.SendEvent(protocol.TypeTerminalResync, protocol.TerminalResync{Ch: a.ch, SessionID: a.sess.id, Reason: reason})
	}
}

// PeerClosed detaches every stream of an ended connection and cancels its
// connection attempts (realtime OnClose). Sessions keep running.
func (m *Manager) PeerClosed(p protocol.Peer) {
	m.mu.Lock()
	ps := m.peers[p.ID()]
	delete(m.peers, p.ID())
	m.mu.Unlock()
	m.cancelAttemptsOf(func(k attemptKey, _ *attempt) bool { return k.peer == p.ID() })
	m.prompts.closePeer(p.ID())
	if ps == nil {
		return
	}
	ps.mu.Lock()
	ps.closed = true
	list := make([]*attachment, 0, len(ps.atts))
	for _, a := range ps.atts {
		list = append(list, a)
	}
	ps.mu.Unlock()
	for _, a := range list {
		m.detach(a, "")
	}
}
