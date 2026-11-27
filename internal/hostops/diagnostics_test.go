package hostops

import (
	"context"
	json "encoding/json/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

const sampleOutput = "cpu=1 2 3 4\nos_name=Debian\nprocess_total=2\nprocess_zombies=0\nprocess_cpu=7|root|sshd|1.5|0.2\n"

func newDiagnostics(t *testing.T) (*Diagnostics, *fakeSessions, *fakeExec) {
	t.Helper()
	s, e := newSessions(), &fakeExec{}
	s.add(1, "s1", Live{Exec: e, ProfileID: "p1", Herdr: true})
	d := &Diagnostics{Sessions: s, Switches: fakeSwitches{herdr: true}, Profiles: fakeProfiles{"p1": {true, false}}}
	d.Routes()
	return d, s, e
}

func asAlice() context.Context { return principal.With(context.Background(), alice) }

func TestInsightsSample(t *testing.T) {
	d, _, e := newDiagnostics(t)
	e.answer = func(line, stdin string) (string, string, int, error) {
		if line != `sh -c 'eval "$(cat)"'` {
			t.Errorf("line %q", line)
		}
		if stdin == insightsDiagnosticsProgram {
			return sampleOutput + "load_1=1\nload_5=1\nload_15=1\ncpu_count=2\n", "", 0, nil
		}
		return sampleOutput, "", 0, nil
	}
	res, err := d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "r1"})
	if err != nil || !res.Success || res.RequestID != "r1" || !strings.Contains(string(res.Stats), `"os_name":"Debian"`) || strings.Contains(string(res.Stats), "load") {
		t.Fatalf("%+v %v", res, err)
	}
	if e.stdins[0] != insightsStatsProgram {
		t.Fatal("stats program not on stdin")
	}
	res, _ = d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "r2", IncludeDiagnostics: true})
	if !strings.Contains(string(res.Stats), `"cpu_count":2`) {
		t.Fatalf("diagnostics %s", res.Stats)
	}
	for _, tc := range []struct {
		answer func(string, string) (string, string, int, error)
		reason string
	}{
		{func(string, string) (string, string, int, error) { return sampleOutput, "", 1, nil }, "unsupported"},
		{func(string, string) (string, string, int, error) { return "nothing\n", "", 0, nil }, "unsupported"},
		{func(string, string) (string, string, int, error) { return "os_name=\xff\n", "", 0, nil }, "unsupported"},
		{func(string, string) (string, string, int, error) {
			return strings.Repeat("x", insightsMaxBytes+1), "", 0, nil
		}, "unsupported"},
		{func(string, string) (string, string, int, error) {
			return "", "", -1, fault.New(fault.ChannelRejected, "")
		}, "resource_shortage"},
		{func(string, string) (string, string, int, error) { return "", "", -1, fault.New(fault.SSHProtocol, "") }, "transient"},
	} {
		e.answer = tc.answer
		d.insightsRate = rateWindow{limit: 100, window: time.Minute}
		res, _ := d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "r"})
		if res.Success || res.Reason != tc.reason || res.Error != "Session insights unavailable" || res.SessionID != "s1" {
			t.Errorf("want %s: %+v", tc.reason, res)
		}
	}
	for _, req := range []protocol.InsightsSample{{SessionID: "", RequestID: "r"}, {SessionID: "s1", RequestID: strings.Repeat("r", 129)}} {
		res, _ := d.handleInsights(asAlice(), nil, req)
		if res.Success || res.SessionID != "" || res.RequestID != "" || res.Reason != "" {
			t.Errorf("invalid ids: %+v", res)
		}
	}
	res, _ = d.handleInsights(principal.With(context.Background(), principal.Principal{UserID: 2, SessionID: "b"}), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "r"})
	if res.Success || res.Reason != "" {
		t.Errorf("foreign session: %+v", res)
	}
}

func TestInsightsPartialSampleAtTheDeadline(t *testing.T) {
	d, _, e := newDiagnostics(t)
	e.answer = nil
	e.release = make(chan struct{})
	// The fake writes nothing before the deadline: transient.
	res, _ := d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "r"})
	if res.Success || res.Reason != "transient" {
		t.Fatalf("%+v", res)
	}
}

func TestInsightsRateAndBusy(t *testing.T) {
	d, _, e := newDiagnostics(t)
	e.answer = func(string, string) (string, string, int, error) { return sampleOutput, "", 0, nil }
	for range insightsPerMin {
		if res, _ := d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "r"}); !res.Success {
			t.Fatalf("%+v", res)
		}
	}
	if res, _ := d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "r"}); res.Success || res.Reason != "" {
		t.Fatalf("over the rate: %+v", res)
	}
	d.insightsRate = rateWindow{limit: 100, window: time.Minute}
	e.release = make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() { d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "a"}) })
	waitFor(t, func() bool { return len(e.calls()) == insightsPerMin+1 })
	if res, _ := d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "s1", RequestID: "b"}); res.Reason != "busy" {
		t.Fatalf("second sample: %+v", res)
	}
	close(e.release)
	wg.Wait()
}

func TestInventorySample(t *testing.T) {
	d, _, e := newDiagnostics(t)
	d.now = fixedClock(time.Unix(1_800_000_000, 0))
	out := "docker_version=27\ndocker_total=1\ndocker_running=1\ndocker_returned=1\ndocker_container=web|Up\npermission_denied=systemd\n"
	e.answer = func(_, stdin string) (string, string, int, error) {
		if stdin != inventoryProgram {
			t.Error("inventory program not on stdin")
		}
		return out, "", 0, nil
	}
	res, err := d.handleInventory(asAlice(), nil, protocol.InventorySample{SessionID: "s1", RequestID: "r"})
	raw, _ := json.Marshal(res)
	if err != nil || !res.Success || res.SampledAt != 1_800_000_000 || res.Systemd != nil ||
		!strings.Contains(string(raw), `"docker":{"version":"27","total":1,"running":1,"returned":1,"truncated":false,"containers":[{"name":"web","status":"Up"}]}`) ||
		!strings.Contains(string(raw), `"permission_denied":["systemd"]`) {
		t.Fatalf("%s %v", raw, err)
	}
	for _, answer := range []func(string, string) (string, string, int, error){
		func(string, string) (string, string, int, error) { return out, "noise", 0, nil },
		func(string, string) (string, string, int, error) { return out, "", 2, nil },
		func(string, string) (string, string, int, error) {
			return strings.Repeat("x", inventoryMaxBytes), "y", 0, nil
		},
	} {
		e.answer = answer
		d.inventoryRate = rateWindow{limit: 100, window: time.Minute}
		res, _ := d.handleInventory(asAlice(), nil, protocol.InventorySample{SessionID: "s1", RequestID: "r"})
		if res.Success || res.Error != "Runtime inventory unavailable" || res.SessionID != "s1" {
			t.Errorf("%+v", res)
		}
	}
}

func herdrOutput(agents string) string {
	return `{"id":1,"result":{"type":"session_snapshot","snapshot":{"agents":[` + agents + `]}}}`
}

func TestHerdrSnapshot(t *testing.T) {
	d, s, e := newDiagnostics(t)
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	e.answer = func(line, _ string) (string, string, int, error) {
		if line != herdrSnapshotCommand {
			t.Errorf("line %q", line)
		}
		return herdrOutput(`{"pane_id":"p1","agent":"claude","name":"fix \u202ebug","cwd":"/srv","agent_status":"working"}`), "", 0, nil
	}
	res, _ := d.handleHerdr(asAlice(), nil, protocol.HerdrSnapshot{SessionID: "s1"})
	if !res.Success || res.Reason != nil || len(res.Agents) != 1 || res.Agents[0].Label != "fix bug" || res.Agents[0].Status != "working" {
		t.Fatalf("%+v", res)
	}
	reason := func(want string) {
		t.Helper()
		res, _ := d.handleHerdr(asAlice(), nil, protocol.HerdrSnapshot{SessionID: "s1"})
		if res.Success || res.Reason == nil || *res.Reason != want || res.Agents == nil {
			t.Fatalf("want %s: %+v", want, res)
		}
	}
	reason("busy") // within four seconds
	now = now.Add(herdrMinInterval)
	e.answer = func(string, string) (string, string, int, error) {
		return "", "{\"error\":{\"code\":\"server_not_running\"}}\n", 1, nil
	}
	reason("no_server")
	now = now.Add(herdrMinInterval)
	e.answer = func(string, string) (string, string, int, error) { return "", "", 127, nil }
	reason("not_installed")
	now = now.Add(herdrMinInterval)
	e.answer = func(string, string) (string, string, int, error) { return "{", "", 0, nil }
	reason("invalid")
	now = now.Add(herdrMinInterval)
	e.answer = func(string, string) (string, string, int, error) {
		return "", "", -1, fault.Wrap(fault.Timeout, context.DeadlineExceeded, "")
	}
	reason("timeout")
	now = now.Add(herdrMinInterval)
	reason("busy") // a host that timed out waits thirty seconds
	now = now.Add(herdrTimeoutInterval)
	e.answer = func(string, string) (string, string, int, error) { return herdrOutput(""), "", 0, nil }
	if res, _ := d.handleHerdr(asAlice(), nil, protocol.HerdrSnapshot{SessionID: "s1"}); !res.Success || len(res.Agents) != 0 {
		t.Fatalf("%+v", res)
	}

	// The saved host lost the option, the session has no overview, the
	// integration is off, the session belongs to someone else.
	now = now.Add(herdrMinInterval)
	d.Profiles = fakeProfiles{}
	reason("not_enabled")
	d.Profiles = fakeProfiles{"p1": {true, false}}
	s.add(1, "s2", Live{Exec: e, ProfileID: "p1"})
	if res, _ := d.handleHerdr(asAlice(), nil, protocol.HerdrSnapshot{SessionID: "s2"}); *res.Reason != "not_enabled" {
		t.Fatalf("%+v", res)
	}
	d.Switches = fakeSwitches{}
	reason("disabled")
	d.Switches = fakeSwitches{herdr: true}
	bob := principal.With(context.Background(), principal.Principal{UserID: 2, SessionID: "b"})
	if res, _ := d.handleHerdr(bob, nil, protocol.HerdrSnapshot{SessionID: "s1"}); *res.Reason != "unavailable" {
		t.Fatalf("%+v", res)
	}
}

func TestHerdrBudgets(t *testing.T) {
	var h herdrState
	now := time.Now()
	var ends []func(time.Time)
	for i, id := range []string{"a", "b"} {
		end, ok := h.begin(1, id, nil, now)
		if !ok {
			t.Fatalf("session %d refused", i)
		}
		ends = append(ends, end)
	}
	if _, ok := h.begin(1, "c", nil, now); ok {
		t.Fatal("a third snapshot of one account ran")
	}
	for _, id := range []string{"d", "e"} {
		end, ok := h.begin(2, id, nil, now)
		if !ok {
			t.Fatal("other account refused")
		}
		ends = append(ends, end)
	}
	if _, ok := h.begin(3, "f", nil, now); ok {
		t.Fatal("more than four snapshots ran")
	}
	for _, end := range ends {
		end(time.Time{})
	}
	if _, ok := h.begin(3, "f", nil, now); !ok {
		t.Fatal("budget not returned")
	}
	done := make(chan struct{})
	if end, ok := h.begin(4, "g", done, now); ok {
		end(time.Time{})
	}
	close(done)
	waitFor(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		_, kept := h.sessions["g"]
		return !kept
	})
}
