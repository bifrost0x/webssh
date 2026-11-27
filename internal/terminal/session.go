package terminal

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Reasons of terminal.closed; the page shows them as the Python release
// sent them.
const (
	reasonClosed    = "Connection closed"
	reasonUser      = "User requested disconnect"
	reasonDiscarded = "Cancelled connection discarded"
	// reasonBackpressure is the reason of terminal.resync_required.
	reasonBackpressure = "backpressure"
)

// stdinFrames bounds queued input frames; QueueBytes bounds their bytes.
const stdinFrames = 64

// Session is one shell. It outlives browser connections: connections
// attach to it and detach again.
type Session struct {
	id      string
	owner   int64
	m       *Manager
	shell   client.Shell
	tmux    *tmuxBinding // nil without tmux; fixed before register
	host    remoteHost   // the session's connection; nil for a shell from Shells
	created time.Time
	//lint:ignore U1000 set and read by the e2e hooks (fixtures.go)
	fixture bool
	opener  uint64 // the connection whose terminal.open created it
	request string // the request_id of that terminal.open
	release func() // quota slot

	mu       sync.Mutex
	info     protocol.SessionInfo
	seq      uint64
	replay   ring
	attached map[*attachment]struct{}
	closed   bool
	activity time.Time
	warned   bool
	queued   int // bytes in stdin
	size     [2]int

	stdin   chan []byte
	resized chan struct{}
	done    chan struct{}
}

// newSessionID returns a random UUID (version 4) in the form of the
// Python release.
func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (m *Manager) newSession(owner int64, shell client.Shell, info protocol.SessionInfo, release func()) *Session {
	now := m.now()
	id := newSessionID()
	info.SessionID = id
	if release == nil {
		release = func() {}
	}
	return &Session{
		id: id, owner: owner, m: m, shell: shell, created: now, release: release,
		info: info, replay: ring{max: m.cfg.ReplayBytes}, attached: map[*attachment]struct{}{},
		activity: now, stdin: make(chan []byte, stdinFrames), resized: make(chan struct{}, 1), done: make(chan struct{}),
	}
}

// register adds s to the manager and reserves its three goroutines, which
// start must then launch. It fails once Shutdown began, and when the
// owner was signed out since gen was read: such a session would outlive
// the revocation.
func (m *Manager) register(s *Session, gen uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return fault.New(fault.Unavailable, "The server is shutting down.")
	}
	if m.revoked[s.owner] != gen {
		return errCancelled
	}
	m.sessions[s.id] = s
	m.wg.Add(3)
	return nil
}

// start runs the reader, the output pump and the writer. notice, if set,
// is the first output of the session.
func (s *Session) start(notice []byte) {
	chunks := make(chan []byte)
	go func() { defer s.m.wg.Done(); s.readLoop(chunks) }()
	go func() { defer s.m.wg.Done(); s.pump(chunks, notice) }()
	go func() { defer s.m.wg.Done(); s.writeLoop() }()
}

// readLoop hands every read to the pump; while the pump waits for output
// credit, the reader waits with at most one read in hand and the shell is
// not read further.
func (s *Session) readLoop(out chan<- []byte) {
	defer close(out)
	buf := make([]byte, s.m.cfg.ReadSize)
	for {
		n, err := s.shell.Read(buf)
		if n > 0 {
			select {
			case out <- append([]byte(nil), buf[:n]...):
			case <-s.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// pump filters device attributes across reads and publishes the output.
// It ends the session when the shell ends.
func (s *Session) pump(in <-chan []byte, notice []byte) {
	defer s.terminateAs(reasonClosed, nil, endProbe)
	s.publish(notice)
	var f daFilter
	hold := time.NewTimer(time.Hour)
	hold.Stop()
	defer hold.Stop()
	for {
		select {
		case <-s.done:
			return
		case b, ok := <-in:
			if !ok {
				s.publish(f.flush())
				return
			}
			s.publish(f.write(b))
			if f.pending() {
				hold.Reset(s.m.cfg.HoldBack)
			} else {
				hold.Stop()
			}
		case <-hold.C:
			s.publish(f.flush())
		}
	}
}

// publish records a chunk and delivers it to every attachment, waiting for
// credit on each. One slow attachment therefore holds back the other tabs
// of the same session until it acknowledges or the sweeper detaches it
// after AckTimeout; the replay buffer lets it catch up by re-attaching.
func (s *Session) publish(data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.seq++
	c := chunk{seq: s.seq, data: data}
	s.replay.add(c)
	s.activity = s.m.now()
	targets := s.attachmentsLocked()
	s.mu.Unlock()
	for _, a := range targets {
		frame := protocol.AppendFrame(make([]byte, 0, protocol.HeaderLen+len(data)),
			protocol.Frame{Kind: protocol.KindOutput, Channel: a.ch, Seq: c.seq, Data: data})
		var sendErr error
		// The peer context ends on disconnect and revocation; nothing is
		// forwarded to such a connection. A detached stream keeps the chunk
		// in the replay buffer.
		_ = s.m.flow.acquire(a.peer.Context(), a.credit, c.seq, len(data), func() error {
			sendErr = a.peer.SendBinary(frame)
			return sendErr
		})
		if sendErr != nil {
			s.m.detach(a, "")
		}
	}
}

func (s *Session) attachmentsLocked() []*attachment {
	out := make([]*attachment, 0, len(s.attached))
	for a := range s.attached {
		out = append(out, a)
	}
	return out
}

func (s *Session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case b := <-s.stdin:
			s.mu.Lock()
			s.queued -= len(b)
			s.mu.Unlock()
			if _, err := s.shell.Write(b); err != nil {
				s.terminateAs(reasonClosed, nil, endProbe)
				return
			}
		case <-s.resized:
			s.mu.Lock()
			rows, cols := s.size[0], s.size[1]
			s.mu.Unlock()
			if err := s.shell.Resize(rows, cols); err != nil {
				s.m.log.Debug("terminal resize failed", "session", s.id, "err", err)
			}
		}
	}
}

// queueStartup puts the startup commands in front of all input. It runs
// before start, so the queue is empty; text that does not fit the queue
// is refused by the protocol bound before it gets here.
func (s *Session) queueStartup(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case s.stdin <- b:
		s.queued += len(b)
	default:
	}
}

// enqueueInput never blocks the connection's read loop.
func (s *Session) enqueueInput(b []byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.queued+len(b) > s.m.cfg.Input.QueueBytes {
		return false
	}
	select {
	case s.stdin <- b:
		s.queued += len(b)
		s.activity = now
		return true
	default:
		return false
	}
}

// resize keeps the latest size; the writer applies it, so a slow remote
// cannot block the read loop and a burst of resizes becomes one.
func (s *Session) resize(rows, cols int) {
	s.mu.Lock()
	s.size = [2]int{rows, cols}
	s.mu.Unlock()
	select {
	case s.resized <- struct{}{}:
	default:
	}
}

// terminate ends the session once: it stops forwarding at once, tells
// every attached connection and requester, and closes the shell in the
// background. It reports whether this call ended the session. A tmux
// session behind it is detached.
func (s *Session) terminate(reason string, requester protocol.Peer) bool {
	return s.terminateAs(reason, requester, endDetach)
}

// terminateAs is terminate with what happens to the tmux session.
func (s *Session) terminateAs(reason string, requester protocol.Peer, end endMode) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.closed = true
	targets := s.attachmentsLocked()
	clear(s.attached)
	s.mu.Unlock()
	close(s.done)
	s.m.remove(s)
	s.release()
	ev := protocol.TerminalClosed{SessionID: s.id, Reason: reason}
	told := map[uint64]bool{}
	for _, a := range targets {
		s.m.dropAttachment(a)
		if !told[a.peer.ID()] {
			told[a.peer.ID()] = true
			_ = a.peer.SendEvent(protocol.TypeTerminalClosed, ev)
		}
	}
	if requester != nil && !told[requester.ID()] {
		_ = requester.SendEvent(protocol.TypeTerminalClosed, ev)
	}
	s.m.spawn(func() { s.m.finish(s.id, s.owner, s.shell, s.tmux, end) })
	return true
}

// broadcast sends an event once to every connection the session is
// attached to.
func (s *Session) broadcast(typ string, payload any) {
	s.mu.Lock()
	targets := s.attachmentsLocked()
	s.mu.Unlock()
	told := map[uint64]bool{}
	for _, a := range targets {
		if !told[a.peer.ID()] {
			told[a.peer.ID()] = true
			_ = a.peer.SendEvent(typ, payload)
		}
	}
}

// snapshot returns the session's description with its last sequence.
func (s *Session) snapshot() (protocol.SessionInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := s.info
	info.LastSeq = s.seq
	return info, !s.closed
}

func (s *Session) touch(now time.Time) {
	s.mu.Lock()
	s.activity = now
	s.mu.Unlock()
}

func (s *Session) rename(name string) {
	s.mu.Lock()
	s.info.DisplayName = name
	s.mu.Unlock()
}

type idleVerdict int

const (
	idleNone idleVerdict = iota
	idleWarn
	idleExpired
)

// idleState applies the idle rules of the Python release: warn once when
// less than warn is left, re-arm on activity, close after timeout.
func (s *Session) idleState(now time.Time, timeout, warn time.Duration) idleVerdict {
	s.mu.Lock()
	defer s.mu.Unlock()
	idle := now.Sub(s.activity)
	switch {
	case s.closed:
		return idleNone
	case idle > timeout:
		return idleExpired
	case idle > timeout-warn:
		if !s.warned {
			s.warned = true
			return idleWarn
		}
	default:
		s.warned = false
	}
	return idleNone
}
