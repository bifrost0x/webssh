package e2eseed

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// fakeHerdr stands in for the terminal: profiles "p<owner>-*" belong to
// the owner; every session keeps its executor.
type fakeHerdr struct {
	mu    sync.Mutex
	n     int
	execs map[string]remotecmd.Executor
	last  map[int64][]string
}

func (f *fakeHerdr) ReplaceHerdrFixtures(_ context.Context, owner int64, ids []string, exec func(string) remotecmd.Executor) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.execs == nil {
		f.execs, f.last = map[string]remotecmd.Executor{}, map[int64][]string{}
	}
	for _, id := range ids {
		if !strings.HasPrefix(id, fmt.Sprintf("p%d-", owner)) {
			return nil, fault.New(fault.NotFound, "")
		}
	}
	var out []string
	for range ids {
		f.n++
		sid := fmt.Sprintf("s%d", f.n)
		f.execs[sid] = exec(sid)
		out = append(out, sid)
	}
	f.last[owner] = out
	return out, nil
}

func (f *fakeHerdr) exec(t *testing.T, sid, line string) (string, error) {
	t.Helper()
	f.mu.Lock()
	e := f.execs[sid]
	f.mu.Unlock()
	var out bytes.Buffer
	_, err := e.Exec(t.Context(), line, nil, &out, &out)
	return out.String(), err
}

const snapshotLine = "sh -c 'PATH=x; herdr api snapshot & p=$!; wait'"

func herdrRoutes(t *testing.T) (*fakeHerdr, protocol.Route, protocol.Route) {
	t.Helper()
	snap, err := LoadHerdrSnapshot(herdrSnapshotPath(checkedInSeed))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeHerdr{}
	r := HerdrRoutes(f, snap)
	if len(r) != 2 || r[0].Type != TypeHerdrSessions || r[1].Type != TypeHerdrExecCount || !r[0].Spec.Mutates {
		t.Fatalf("routes = %v", r)
	}
	return f, r[0], r[1]
}

func TestHerdrSnapshotAddsTheHostileAgent(t *testing.T) {
	t.Parallel()
	snap, err := LoadHerdrSnapshot(herdrSnapshotPath(checkedInSeed))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Result struct {
			Snapshot struct {
				Agents []map[string]any `json:"agents"`
			} `json:"snapshot"`
		} `json:"result"`
	}
	if !bytes.HasSuffix(snap, []byte("\n")) || json.Unmarshal(bytes.TrimSpace(snap), &doc) != nil {
		t.Fatalf("snapshot = %q", snap)
	}
	agents := doc.Result.Snapshot.Agents
	if len(agents) != 4 || agents[3]["name"] != `<img src=x onerror="window.__herdrInjected=1">` || agents[3]["pane_id"] != "w1:p9" {
		t.Fatalf("agents = %v", agents)
	}
	if _, err := LoadHerdrSnapshot("missing.json"); err == nil {
		t.Error("missing snapshot accepted")
	}
}

func TestHerdrSessionsAndCount(t *testing.T) {
	t.Parallel()
	f, seed, count := herdrRoutes(t)
	peer := protocoltest.NewPeer(t, alice)
	other := protocoltest.NewPeer(t, principal.Principal{UserID: 99, SessionID: "s-bob", Username: "bob"})
	own := fmt.Sprintf("p%d-a", alice.UserID)

	out, werr := call(t, seed, peer, map[string]any{"profile_ids": []string{own, own}})
	if werr != nil || out["ok"] != true || len(out["session_ids"].([]any)) != 2 {
		t.Fatalf("seed = %v, %v", out, werr)
	}
	sid := out["session_ids"].([]any)[0].(string)
	text, err := f.exec(t, sid, snapshotLine)
	if err != nil || !strings.Contains(text, "window.__herdrInjected=2") {
		t.Fatalf("snapshot = %q, %v", text, err)
	}
	if _, err := f.exec(t, sid, "uname -a"); err == nil {
		t.Error("other command accepted")
	}
	if out, _ := call(t, count, peer, struct{}{}); out["ok"] != true || out["count"] != float64(1) {
		t.Fatalf("count = %v", out)
	}
	if out, _ := call(t, count, other, struct{}{}); out["count"] != float64(0) {
		t.Fatalf("other's count = %v", out)
	}
	// Someone else's host: nothing created, the answer is ok false.
	if out, werr := call(t, seed, other, map[string]any{"profile_ids": []string{own}}); werr != nil || out["ok"] != false {
		t.Fatalf("foreign profile = %v, %v", out, werr)
	}
	// An empty list clears the caller's fixtures and their counts.
	if out, werr := call(t, seed, peer, map[string]any{"profile_ids": []string{}}); werr != nil || out["ok"] != true {
		t.Fatalf("clear = %v, %v", out, werr)
	}
	if out, _ := call(t, count, peer, struct{}{}); out["count"] != float64(0) {
		t.Fatalf("count after clear = %v", out)
	}
}

func TestHerdrSessionsValidation(t *testing.T) {
	t.Parallel()
	_, seed, count := herdrRoutes(t)
	peer := protocoltest.NewPeer(t, alice)
	many := make([]string, 13)
	for i := range many {
		many[i] = fmt.Sprintf("p%d-%d", alice.UserID, i)
	}
	for _, bad := range []any{map[string]any{"profile_ids": many}, map[string]any{"profile_ids": "x"},
		map[string]any{"profile_ids": []any{1}}, map[string]any{"profile_ids": []string{}, "owner": 1}} {
		if _, werr := call(t, seed, peer, bad); werr == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if out, werr := call(t, seed, peer, map[string]any{"profile_ids": many[:12]}); werr != nil || out["ok"] != true {
		t.Fatalf("12 profiles = %v, %v", out, werr)
	}
	nobody := protocoltest.NewPeer(t, principal.Principal{})
	for _, r := range []protocol.Route{seed, count} {
		if _, werr := call(t, r, nobody, map[string]any{}); werr == nil || werr.Code != fault.AuthenticationNeeded {
			t.Errorf("%s without principal = %v", r.Type, werr)
		}
	}
}

func TestHerdrExecHonoursCancellation(t *testing.T) {
	t.Parallel()
	f := newHerdrFixtures(&fakeHerdr{}, []byte("{}\n"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.executor("s").Exec(ctx, snapshotLine, nil, &bytes.Buffer{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled exec = %v", err)
	}
}
