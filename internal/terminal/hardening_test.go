package terminal

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Output in 1-byte reads keeps the replay buffer small in heap and cheap
// per read (review 1: bytes alone did not bound the chunk list).
func TestRingSmallReadsBounded(t *testing.T) {
	r := ring{max: DefaultReplayBytes}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const n = 1_500_000
	start := time.Now()
	for i := range n {
		r.add(chunk{seq: uint64(i + 1), data: []byte{'x'}})
		if i%10000 == 0 && time.Since(start) > 10*time.Second {
			t.Fatalf("%d one-byte reads took %v", i, time.Since(start))
		}
	}
	per := time.Since(start) / n
	runtime.GC()
	runtime.ReadMemStats(&after)
	if len(r.chunks) > maxRingChunks {
		t.Fatalf("%d chunks for %d bytes", len(r.chunks), r.size)
	}
	if grow := int64(after.HeapAlloc) - int64(before.HeapAlloc); grow > 4<<20 {
		t.Fatalf("replay buffer of %d bytes holds %d bytes of heap", r.size, grow)
	}
	if per > 5*time.Microsecond {
		t.Fatalf("%v per one-byte read", per)
	}
	if r.size > r.max || r.size < r.max-mergeLimit {
		t.Fatalf("size %d of %d", r.size, r.max)
	}
	// A delta inside a merged chunk cannot be cut exactly: full replay.
	last := r.chunks[len(r.chunks)-1]
	if _, full := r.since(last.seq - 1); !full {
		t.Fatal("delta inside a merged chunk is not a full replay")
	}
	if out, full := r.since(last.first - 1); full || len(out) != 1 {
		t.Fatalf("delta at a chunk boundary: %d chunks, full %v", len(out), full)
	}
	runtime.KeepAlive(&r)
}

// keepReasons is the expected classification of every principal.Reason.
// A new reason fails this test until it is classified here, and the
// manager ends terminals for any reason it does not know (review 2).
var keepReasons = map[principal.Reason]bool{
	principal.ReasonLogout:          false,
	principal.ReasonRevokedByUser:   true,
	principal.ReasonPasswordChanged: false,
	principal.ReasonFactorChanged:   false,
	principal.ReasonAccountLocked:   false,
	principal.ReasonRoleChanged:     false,
	principal.ReasonExpired:         true,
	principal.ReasonRecoveryEnded:   true,
	// A refused directory check ends access everywhere, like a lock.
	principal.ReasonDirectoryRefused: false,
}

func TestEveryReasonClassified(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "principal", "revocation.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || vs.Type == nil || len(vs.Values) == 0 {
			return true
		}
		if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Reason" {
			return true
		}
		lit, _ := vs.Values[0].(*ast.BasicLit)
		value, _ := strconv.Unquote(lit.Value)
		want, ok := keepReasons[principal.Reason(value)]
		if !ok {
			t.Errorf("reason %q is not classified", value)
		}
		if got := keepsTerminals(principal.Reason(value)); got != want {
			t.Errorf("reason %q keeps terminals: %v, want %v", value, got, want)
		}
		seen++
		return true
	})
	if seen != len(keepReasons) {
		t.Fatalf("%d reasons in principal, %d classified", seen, len(keepReasons))
	}
	if keepsTerminals("deprovisioned") {
		t.Fatal("an unknown reason keeps terminals (fail open)")
	}
	m := newManager(t, Config{}, &fakeShells{})
	peer := user(t, 1)
	open(t, m, peer, 1)
	m.Revoked(principal.Revocation{SessionID: "s", UserID: 1, Reason: "deprovisioned"})
	if len(m.sessionsOf(1)) != 0 {
		t.Fatal("a session survived a revocation with a new reason")
	}
}

// A session committed while its user is being signed out does not
// survive (review 3).
func TestRegisterAfterRevocation(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	gen := m.generation(1)
	m.Revoked(principal.Revocation{SessionID: "s", UserID: 1, Reason: principal.ReasonLogout})
	s := m.newSession(1, newFakeShell(), protocol.SessionInfo{}, nil)
	if err := m.register(s, gen); fault.CodeOf(err) != fault.Cancelled {
		t.Fatalf("register after revocation: %v", err)
	}
	other := m.newSession(2, newFakeShell(), protocol.SessionInfo{}, nil)
	if err := m.register(other, m.generation(2)); err != nil {
		t.Fatalf("another user: %v", err)
	}
	other.start(nil)
}

// hangingShell never returns from Close.
type hangingShell struct {
	*fakeShell
	release chan struct{}
}

func (h hangingShell) Close() error { <-h.release; return h.fakeShell.Close() }

type hangingShells struct{ release chan struct{} }

func (h hangingShells) OpenShell(context.Context, client.Target, client.Interaction, int, int) (client.Shell, error) {
	return hangingShell{newFakeShell(), h.release}, nil
}

// Shutdown keeps to its context even when a shell does not close
// (review 4).
func TestShutdownHonoursContext(t *testing.T) {
	release := make(chan struct{})
	m, err := New(Config{}, Deps{Shells: hangingShells{release}, Log: newManager(t, Config{}, &fakeShells{}).log})
	if err != nil {
		t.Fatal(err)
	}
	defer close(release)
	open(t, m, user(t, 1), 1)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Shutdown(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Shutdown reported success with a shell still closing")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown ignored its context")
	}
	if werr := call(t, m, user(t, 1), protocol.TypeTerminalOpen, openReq(1, "late"), nil); werr == nil {
		t.Fatal("open after Shutdown")
	}
}

// gatePeer holds its first live output frame inside SendBinary until the
// test opens the gate.
type gatePeer struct {
	*peerT
	entered, gate chan struct{}
	once          sync.Once
	mu            sync.Mutex
	afterDetach   int
	detached      bool
}

func (g *gatePeer) SendBinary(frame []byte) error {
	if frame[1]&protocol.FlagReplay == 0 {
		g.once.Do(func() { close(g.entered); <-g.gate })
	}
	g.mu.Lock()
	if g.detached {
		g.afterDetach++
	}
	g.mu.Unlock()
	return g.peerT.SendBinary(frame)
}

// After detach returns, no frame reaches the freed channel (review 5): a
// send in progress finishes before detach returns.
func TestNoOutputAfterDetach(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{}, shells)
	res := open(t, m, user(t, 1), 1)
	p := &gatePeer{peerT: user(t, 1), entered: make(chan struct{}), gate: make(chan struct{})}
	if werr := call(t, m, p, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 2, SessionID: res.SessionID}, nil); werr != nil {
		t.Fatal(werr)
	}
	sh := shells.last(t)
	go func() { sh.out <- []byte("x") }()
	<-p.entered
	detached := make(chan struct{})
	go func() {
		m.detach(m.attachmentOf(p, 2), "")
		p.mu.Lock()
		p.detached = true
		p.mu.Unlock()
		close(detached)
	}()
	time.Sleep(20 * time.Millisecond)
	close(p.gate)
	<-detached
	time.Sleep(20 * time.Millisecond)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.afterDetach != 0 {
		t.Fatalf("%d frames sent after detach returned", p.afterDetach)
	}
}

// A stream detached for backpressure cannot re-attach at once (review 6).
func TestReattachCooldownAfterBackpressure(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{Flow: FlowLimits{AckTimeout: 50 * time.Millisecond}, SweepEvery: 10 * time.Millisecond}, shells)
	peer := user(t, 1)
	res := open(t, m, peer, 1)
	shells.last(t).push(t, "x")
	eventually(t, "resync", func() bool { return len(peer.Events(protocol.TypeTerminalResync)) == 1 })
	werr := call(t, m, peer, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 2, SessionID: res.SessionID}, nil)
	if werr == nil || werr.Code != fault.Backpressure || werr.RetryAfterMS < 1 {
		t.Fatalf("immediate re-attach: %+v", werr)
	}
	time.Sleep(time.Duration(werr.RetryAfterMS+20) * time.Millisecond)
	if werr := call(t, m, peer, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 2, SessionID: res.SessionID}, nil); werr != nil {
		t.Fatalf("re-attach after the cooldown: %+v", werr)
	}
	// Another connection is not held back.
	if werr := call(t, m, user(t, 1), protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 2, SessionID: res.SessionID}, nil); werr != nil {
		t.Fatalf("other connection: %+v", werr)
	}
}

// The ledger forgets users without credits (review 7).
func TestLedgerForgetsUsers(t *testing.T) {
	l := newLedger(limits())
	for u := range int64(100) {
		l.close(l.open(uint64(u), u))
	}
	if len(l.users) != 0 || len(l.conns) != 0 {
		t.Fatalf("%d users, %d connections left", len(l.users), len(l.conns))
	}
}

// Only the connection that started an attempt discards its late session,
// and only with the attempt's request id (review 8; Python matched the
// client_request_id of the attempt). open uses request id "rb" for
// channel 1.
func TestDiscardLateOnlyByOpener(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	opener := user(t, 1)
	res := open(t, m, opener, 1)
	if werr := call(t, m, user(t, 1), protocol.TypeTerminalDiscardLate, protocol.SessionRef{SessionID: res.SessionID, RequestID: "rb"}, nil); werr == nil || werr.Code != fault.NotFound {
		t.Fatalf("discard from another connection: %+v", werr)
	}
	for _, id := range []string{"", "other"} {
		if werr := call(t, m, opener, protocol.TypeTerminalDiscardLate, protocol.SessionRef{SessionID: res.SessionID, RequestID: id}, nil); werr == nil || werr.Code != fault.NotFound {
			t.Fatalf("discard with request id %q: %+v", id, werr)
		}
	}
	if werr := call(t, m, opener, protocol.TypeTerminalDiscardLate, protocol.SessionRef{SessionID: res.SessionID, RequestID: "rb"}, nil); werr != nil {
		t.Fatal(werr)
	}
}
