package terminal

import (
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

func TestOpenStreamsOutputAndInput(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{}, shells)
	peer := user(t, 1)
	res := open(t, m, peer, 1)
	if res.SessionID == "" || res.Info.SessionID != res.SessionID || res.Info.Host != "h.example" ||
		res.Info.AuthType != "password" || !res.Info.ReconnectRouteKnown {
		t.Fatalf("result %+v", res)
	}
	sh := shells.last(t)
	sh.push(t, "hello ")
	sh.push(t, "world")
	eventually(t, "output", func() bool { return output(t, peer, 1) == "hello world" })
	for i, f := range frames(t, peer) {
		if f.Seq != uint64(i+1) || f.Flags != 0 {
			t.Fatalf("frame %d: seq %d flags %d", i, f.Seq, f.Flags)
		}
	}
	if err := m.HandleBinary(peer, input(1, 1, "ls\r", true)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "input", func() bool { return sh.typed() == "ls\r" })
	if acks := peer.Events(protocol.TypeTerminalInputAck); len(acks) != 1 {
		t.Fatalf("input acks %d", len(acks))
	}
	// A frame of the output kind from a client is a protocol violation.
	if err := m.HandleBinary(peer, protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindOutput, Channel: 1, Seq: 1})); err == nil {
		t.Fatal("output frame from the client accepted")
	}
	// An input frame above SSH_INPUT_MAX_BYTES closes the connection.
	if err := m.HandleBinary(peer, input(1, 2, strings.Repeat("x", 128<<10+1), false)); err == nil {
		t.Fatal("oversized input frame accepted")
	}
}

// Go-Back-N: a refused frame gets one rejection, later frames are dropped
// silently until the refused sequence comes again.
func TestInputGoBackN(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{Input: InputLimits{SessionRate: 1000, SessionBurst: 10, UserRate: 1000, UserBurst: 100}}, shells)
	peer := user(t, 1)
	open(t, m, peer, 1)
	sh := shells.last(t)
	mustBinary := func(b []byte) {
		if err := m.HandleBinary(peer, b); err != nil {
			t.Fatal(err)
		}
	}
	mustBinary(input(1, 1, "12345678", false)) // 8 of 10 tokens
	mustBinary(input(1, 2, "abcdef", false))   // refused
	mustBinary(input(1, 3, "x", false))        // dropped
	mustBinary(input(1, 5, "y", false))        // dropped
	mustBinary(input(1, 1, "dup", false))      // duplicate, dropped
	rej := peer.Events(protocol.TypeTerminalInputReject)
	if len(rej) != 1 {
		t.Fatalf("%d rejections, want one per refusal", len(rej))
	}
	r := decode[protocol.TerminalInputRejected](t, rej[0])
	if r.Ch != 1 || r.ISeq != 2 || r.Code != fault.InputBackpressure || r.RetryAfterMS < 1 {
		t.Fatalf("rejection %+v", r)
	}
	time.Sleep(10 * time.Millisecond)
	mustBinary(input(1, 2, "ab", false)) // resent, fits now
	mustBinary(input(1, 3, "c", false))
	eventually(t, "input in order", func() bool { return sh.typed() == "12345678abc" })
	if len(peer.Events(protocol.TypeTerminalInputReject)) != 1 {
		t.Fatal("accepted frames were rejected")
	}
}

// The queue towards a shell that does not read is bounded in bytes.
func TestInputQueueBound(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{Input: InputLimits{QueueBytes: 10}}, shells)
	peer := user(t, 1)
	open(t, m, peer, 1)
	sh := shells.last(t)
	sh.block = make(chan struct{})
	sess := m.sessionsOf(1)[0]
	for i, s := range []string{"aaaa", "bbbb", "cccc", "dddd"} {
		if err := m.HandleBinary(peer, input(1, uint64(i+1), s, false)); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			eventually(t, "writer holds the first frame", func() bool {
				sess.mu.Lock()
				defer sess.mu.Unlock()
				return sess.queued == 0
			})
		}
	}
	// The writer holds the first frame; 8 bytes fit the queue behind it.
	if rej := peer.Events(protocol.TypeTerminalInputReject); len(rej) != 1 || decode[protocol.TerminalInputRejected](t, rej[0]).ISeq != 4 {
		t.Fatalf("rejections %v", rej)
	}
	close(sh.block)
	eventually(t, "queued input", func() bool { return sh.typed() == "aaaabbbbcccc" })
}

// Device-attribute replies typed back by xterm.js never reach the shell,
// and queries from the host never reach the browser.
func TestDeviceAttributesFiltered(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{}, shells)
	peer := user(t, 1)
	open(t, m, peer, 1)
	sh := shells.last(t)
	sh.push(t, "a\x1b[")
	sh.push(t, "?1;2cb")
	eventually(t, "filtered output", func() bool { return output(t, peer, 1) == "ab" })
	if err := m.HandleBinary(peer, input(1, 1, "\x1b[?1;2c", true)); err != nil {
		t.Fatal(err)
	}
	if err := m.HandleBinary(peer, input(1, 2, "x\x1b[>0;1;0c", false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "input", func() bool { return sh.typed() == "x" })
	if len(peer.Events(protocol.TypeTerminalInputAck)) != 1 {
		t.Fatal("a frame that is all reply is still acknowledged")
	}
	// A lone prefix is sent after the hold-back time.
	sh.push(t, "\x1b[1")
	eventually(t, "held prefix", func() bool { return output(t, peer, 1) == "ab\x1b[1" })
}

// Replay frames come before the result and carry sequences up to its
// watermark; a delta after_seq replays only what is missing.
func TestAttachReplay(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{}, shells)
	first := user(t, 1)
	res := open(t, m, first, 1)
	sh := shells.last(t)
	for _, s := range []string{"one ", "two ", "three"} {
		sh.push(t, s)
	}
	eventually(t, "output", func() bool { return output(t, first, 1) == "one two three" })

	second := user(t, 1)
	var att protocol.TerminalAttached
	if werr := call(t, m, second, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 7, SessionID: res.SessionID}, &att); werr != nil {
		t.Fatal(werr)
	}
	fs := frames(t, second)
	if att.Seq != 3 || !att.Full || len(fs) != 1 || string(fs[0].Data) != "one two three" ||
		fs[0].Flags != protocol.FlagReplay|protocol.FlagReset || fs[0].Seq != 3 || fs[0].Channel != 7 {
		t.Fatalf("full replay: %+v, frames %+v", att, fs)
	}
	sh.push(t, "!")
	eventually(t, "live after replay", func() bool { return output(t, second, 7) == "one two three!" })
	if f := frames(t, second)[1]; f.Seq != 4 || f.Flags != 0 {
		t.Fatalf("live frame %+v", f)
	}

	third := user(t, 1)
	if werr := call(t, m, third, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 1, SessionID: res.SessionID, AfterSeq: 2}, &att); werr != nil {
		t.Fatal(werr)
	}
	// Small reads share a chunk, so a delta inside it is a full replay;
	// exact deltas at chunk boundaries are tested on the ring.
	if fs := frames(t, third); !att.Full || att.Seq != 4 || len(fs) != 1 || string(fs[0].Data) != "one two three!" || fs[0].Flags != protocol.FlagReplay|protocol.FlagReset {
		t.Fatalf("delta: %+v %+v", att, fs)
	}
	// Up to date: nothing is replayed.
	fourth := user(t, 1)
	if werr := call(t, m, fourth, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 1, SessionID: res.SessionID, AfterSeq: 4}, &att); werr != nil || len(fourth.Frames()) != 0 {
		t.Fatalf("up to date: %v, %d frames", werr, len(fourth.Frames()))
	}
	// Another user cannot see or attach the session.
	if werr := call(t, m, user(t, 2), protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 1, SessionID: res.SessionID}, nil); werr == nil || werr.Code != fault.NotFound {
		t.Fatalf("foreign attach: %+v", werr)
	}
	// A channel in use is refused; detach frees it and is idempotent.
	if werr := call(t, m, third, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 1, SessionID: res.SessionID}, nil); werr == nil || werr.Code != fault.ChannelInUse {
		t.Fatalf("channel reuse: %+v", werr)
	}
	for range 2 {
		if werr := call(t, m, third, protocol.TypeTerminalDetach, protocol.ChannelRef{Ch: 1}, nil); werr != nil {
			t.Fatal(werr)
		}
	}
	if m.attachmentOf(third, 1) != nil {
		t.Fatal("detach left the channel bound")
	}
}

// Output that a browser does not acknowledge holds the shell back; an
// overdue acknowledgement detaches only that stream.
func TestBackpressureAndResync(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{Flow: FlowLimits{StreamFrames: 2, AckTimeout: 200 * time.Millisecond}, SweepEvery: 20 * time.Millisecond}, shells)
	peer := user(t, 1)
	res := open(t, m, peer, 1)
	sh := shells.last(t)
	sh.push(t, "a")
	sh.push(t, "b")
	sh.push(t, "c") // waits for credit in the pump
	sh.push(t, "d") // the one read the reader holds
	select {
	case sh.out <- []byte("e"):
		t.Fatal("the shell was read while the stream had no credit")
	case <-time.After(50 * time.Millisecond):
	}
	if err := m.HandleBinary(peer, ack(1, 2)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "output after ack", func() bool { return output(t, peer, 1) == "abcd" })
	eventually(t, "resync", func() bool { return len(peer.Events(protocol.TypeTerminalResync)) == 1 })
	r := decode[protocol.TerminalResync](t, peer.Events(protocol.TypeTerminalResync)[0])
	if r.Ch != 1 || r.SessionID != res.SessionID || r.Reason != "backpressure" || m.attachmentOf(peer, 1) != nil {
		t.Fatalf("resync %+v", r)
	}
	if st := m.Stats(); st.Sessions != 1 || st.InFlightFrames != 0 {
		t.Fatalf("stats after resync %+v", st)
	}
}

// A connection that ended (revoked) stops holding the session back at
// once, before OnClose detaches it: other attachments keep their output.
func TestEndedPeerReleasesOutput(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{Flow: FlowLimits{StreamFrames: 1}}, shells)
	stalled, live := user(t, 1), user(t, 1)
	res := open(t, m, stalled, 1)
	if werr := call(t, m, live, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 1, SessionID: res.SessionID}, nil); werr != nil {
		t.Fatal(werr)
	}
	sh := shells.last(t)
	sh.push(t, "a")
	eventually(t, "first frame", func() bool { return output(t, live, 1) == "a" })
	if err := m.HandleBinary(live, ack(1, 1)); err != nil {
		t.Fatal(err)
	}
	// "b" waits for the stalled connection's credit, whichever stream is
	// served first, so "c" cannot reach the live one.
	sh.push(t, "b")
	go func() { sh.out <- []byte("c") }()
	time.Sleep(30 * time.Millisecond)
	if strings.Contains(output(t, live, 1), "c") {
		t.Fatal("the stalled stream did not hold the session back")
	}
	stalled.Close()
	eventually(t, "output after the stalled connection ended", func() bool {
		fs := frames(t, live)
		_ = m.HandleBinary(live, ack(1, fs[len(fs)-1].Seq))
		return output(t, live, 1) == "abc"
	})
}
