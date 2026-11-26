package e2eseed

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

var alice = principal.Principal{UserID: 7, SessionID: "s-alice", Username: "alice"}

// fakeFlow accepts frames after delay and tracks the unacknowledged ones
// like a terminal flow with an acknowledgement budget.
type fakeFlow struct {
	delay   time.Duration
	mu      sync.Mutex
	frames  map[string][]uint64
	first   map[string][]byte
	pending int
	fail    string
}

func newFakeFlow(delay time.Duration) *fakeFlow {
	return &fakeFlow{delay: delay, frames: map[string][]uint64{}, first: map[string][]byte{}}
}

func (f *fakeFlow) Emit(ctx context.Context, _ protocol.Peer, stream string, seq uint64, data []byte) error {
	if stream == f.fail && seq == 3 {
		return errors.New("stream gone")
	}
	f.mu.Lock()
	f.pending++
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.pending--; f.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(f.delay):
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames[stream] = append(f.frames[stream], seq)
	if seq == 1 {
		f.first[stream] = data
	}
	return nil
}

func (f *fakeFlow) InFlight(protocol.Peer) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pending
}

func call(t *testing.T, route protocol.Route, peer protocol.Peer, payload any) (map[string]any, *protocol.Error) {
	t.Helper()
	raw, werr := protocoltest.Call(t.Context(), route, peer, payload)
	if werr != nil {
		return nil, werr
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out, nil
}

func loadDone(t *testing.T, peer *protocoltest.Peer) OutputLoadDone {
	t.Helper()
	events := peer.Events(TypeOutputLoadDone)
	if len(events) != 1 {
		t.Fatalf("%d done events", len(events))
	}
	var d OutputLoadDone
	if err := json.Unmarshal(events[0].Payload, &d, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestOutputLoadDeliversAllFramesOnTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		flow := newFakeFlow(time.Millisecond)
		peer := protocoltest.NewPeer(t, alice)
		route := OutputLoadRoute(flow)
		out, werr := call(t, route, peer, struct{}{})
		if werr != nil || out["ok"] != true {
			t.Fatalf("start = %v, %v", out, werr)
		}
		synctest.Wait()
		time.Sleep(13 * time.Second)
		synctest.Wait()
		d := loadDone(t, peer)
		if d.Aborted || len(d.Counts) != loadStreams {
			t.Fatalf("done = %+v", d)
		}
		for i, n := range d.Counts {
			if n != loadFrames {
				t.Fatalf("stream %d delivered %d frames", i, n)
			}
		}
		// 240 slots of 50 ms: the last frame is due after 11.95 s.
		if d.ElapsedMS < 11950 || d.ElapsedMS > 12100 {
			t.Fatalf("elapsed %d ms", d.ElapsedMS)
		}
		if d.Peak < 1 || d.Peak > loadStreams {
			t.Fatalf("peak %d", d.Peak)
		}
		frame := string(flow.first["load-3"])
		if !strings.HasPrefix(frame, "\x1b[?1049h") || !strings.HasSuffix(frame, "stream-3 frame-1 END") {
			t.Fatalf("first frame %q", frame[:20])
		}
		for _, seqs := range flow.frames {
			for i, seq := range seqs {
				if seq != uint64(i+1) {
					t.Fatal("frames out of order")
				}
			}
		}
	})
}

func TestOutputLoadStopsAtBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		flow := newFakeFlow(time.Second)
		flow.fail = "load-0"
		peer := protocoltest.NewPeer(t, alice)
		if _, werr := call(t, OutputLoadRoute(flow), peer, struct{}{}); werr != nil {
			t.Fatal(werr)
		}
		time.Sleep(40 * time.Second)
		synctest.Wait()
		d := loadDone(t, peer)
		if !d.Aborted || d.Counts[0] != 2 || d.Counts[1] < 30 || d.Counts[1] >= loadFrames {
			t.Fatalf("done = %+v", d)
		}
		if d.ElapsedMS < 35000 || d.ElapsedMS > 36100 {
			t.Fatalf("elapsed %d ms", d.ElapsedMS)
		}
		if d.Peak != loadStreams {
			t.Fatalf("peak %d, want every stream held back", d.Peak)
		}
	})
}

func TestOutputLoadOnePerConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		flow := newFakeFlow(time.Millisecond)
		route := OutputLoadRoute(flow)
		peer, other := protocoltest.NewPeer(t, alice), protocoltest.NewPeer(t, alice)
		if _, werr := call(t, route, peer, struct{}{}); werr != nil {
			t.Fatal(werr)
		}
		if _, werr := call(t, route, peer, struct{}{}); werr == nil || werr.Code != fault.Busy {
			t.Fatalf("second load = %v", werr)
		}
		if _, werr := call(t, route, other, struct{}{}); werr != nil {
			t.Fatalf("other connection = %v", werr)
		}
		time.Sleep(13 * time.Second)
		synctest.Wait()
		if _, werr := call(t, route, peer, struct{}{}); werr != nil {
			t.Fatalf("load after the first finished = %v", werr)
		}
		peer.Close()
		other.Close()
		synctest.Wait()
	})
}

func TestOutputLoadEndsWithConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		flow := newFakeFlow(time.Millisecond)
		peer := protocoltest.NewPeer(t, alice)
		if _, werr := call(t, OutputLoadRoute(flow), peer, struct{}{}); werr != nil {
			t.Fatal(werr)
		}
		time.Sleep(time.Second)
		peer.Close()
		// Every producer returns: synctest fails the test on a leaked,
		// durably blocked goroutine when the bubble ends.
		synctest.Wait()
		if n := len(flow.frames["load-0"]); n == 0 || n > 25 {
			t.Fatalf("load-0 delivered %d frames", n)
		}
	})
}

func TestHookRoutesRequireAPrincipal(t *testing.T) {
	t.Parallel()
	nobody := protocoltest.NewPeer(t, principal.Principal{})
	for _, route := range []protocol.Route{OutputLoadRoute(newFakeFlow(0)), WorkspaceRestoreRoute(&fakeSessions{})} {
		if _, werr := call(t, route, nobody, struct{}{}); werr == nil || werr.Code != fault.AuthenticationNeeded {
			t.Errorf("%s without principal = %v", route.Type, werr)
		}
	}
}

type fakeSessions struct {
	owner int64
	count int
	err   error
}

func (f *fakeSessions) ReplaceFixtureSessions(_ context.Context, _ protocol.Peer, owner int64, count int) ([]string, error) {
	f.owner, f.count = owner, count
	if f.err != nil {
		return nil, f.err
	}
	var ids []string
	for range count {
		ids = append(ids, "fixture")
	}
	return ids, nil
}

func TestWorkspaceRestore(t *testing.T) {
	t.Parallel()
	peer := protocoltest.NewPeer(t, alice)
	sessions := &fakeSessions{}
	route := WorkspaceRestoreRoute(sessions)
	if !route.Spec.Mutates {
		t.Fatal("restore must re-check the session")
	}
	out, werr := call(t, route, peer, map[string]any{"count": 3})
	if werr != nil || out["ok"] != true || len(out["session_ids"].([]any)) != 3 || sessions.owner != alice.UserID {
		t.Fatalf("count 3 = %v, %v, owner %d", out, werr, sessions.owner)
	}
	out, werr = call(t, route, peer, map[string]any{"count": 0})
	if werr != nil || out["session_ids"] == nil || len(out["session_ids"].([]any)) != 0 {
		t.Fatalf("count 0 = %v, %v", out, werr)
	}
	if _, werr = call(t, route, peer, struct{}{}); werr != nil || sessions.count != 1 {
		t.Fatalf("default count = %d, %v", sessions.count, werr)
	}
	for _, bad := range []any{-1, 13, true, 1.5, "2", nil} {
		if _, werr := call(t, route, peer, map[string]any{"count": bad}); werr == nil || werr.Code != fault.InvalidRequest {
			t.Errorf("count %v = %v", bad, werr)
		}
	}
	if _, werr := call(t, route, peer, map[string]any{"count": 1, "owner": 1}); werr == nil {
		t.Error("unknown member accepted")
	}
	sessions.err = fault.New(fault.Unavailable, "")
	if _, werr := call(t, route, peer, map[string]any{"count": 1}); werr == nil || werr.Code != fault.Unavailable {
		t.Errorf("provider error = %v", werr)
	}
}

func TestRoutesFollowTheHooks(t *testing.T) {
	t.Parallel()
	s := loadSeed(t)
	routes, err := s.Routes(Hooks{OutputFlow: newFakeFlow(0), FixtureSessions: &fakeSessions{}})
	if err != nil || len(routes) != 2 || routes[0].Type != TypeOutputLoad || routes[1].Type != TypeWorkspaceRestore {
		t.Fatalf("routes = %v, %v", routes, err)
	}
	for _, h := range []Hooks{{OutputFlow: newFakeFlow(0)}, {FixtureSessions: &fakeSessions{}}} {
		if _, err := s.Routes(h); err == nil {
			t.Error("hook without provider accepted")
		}
	}
	s.TestHooks = nil
	if routes, err := s.Routes(Hooks{}); err != nil || len(routes) != 0 {
		t.Fatalf("no hooks: %v, %v", routes, err)
	}
	for _, typ := range []string{TypeOutputLoad, TypeOutputLoadDone, TypeWorkspaceRestore} {
		if _, ok := protocol.Lookup(typ); ok {
			t.Errorf("%s is in the release catalog", typ)
		}
	}
}
