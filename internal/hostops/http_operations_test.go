package hostops

import (
	"bytes"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

var stepUpRequired = fault.New(fault.StepUpRequired, "")

type opsFixture struct {
	ops      *Operations
	sessions *fakeSessions
	exec     *fakeExec
	stepup   *fakeStepUp
	audit    *fakeAudit
	mux      *http.ServeMux
}

var alice = principal.Principal{UserID: 1, SessionID: "auth-a", Username: "alice"}

func newOps(t *testing.T, enabled bool) *opsFixture {
	t.Helper()
	f := &opsFixture{sessions: newSessions(), exec: &fakeExec{}, stepup: &fakeStepUp{}, audit: &fakeAudit{}, mux: http.NewServeMux()}
	f.ops = &Operations{Sessions: f.sessions, Switches: fakeSwitches{ops: enabled}, StepUp: f.stepup, Audit: f.audit}
	f.ops.Register(f.mux)
	f.sessions.add(1, "s1", Live{Exec: f.exec, Host: "example.test", Port: 22, Username: "deploy"})
	return f
}

// call sends a request as p and decodes the JSON answer.
func (f *opsFixture) call(t *testing.T, p principal.Principal, method, path, body string, header ...string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if p.Valid() {
		r = r.WithContext(principal.With(r.Context(), p))
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: %d %q", method, path, w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("answer may be cached")
	}
	return w.Code, out
}

func wantCode(t *testing.T, status int, body map[string]any, wantStatus int, code string) {
	t.Helper()
	if status != wantStatus || body["code"] != code {
		t.Fatalf("got %d %v, want %d %s", status, body, wantStatus, code)
	}
}

func TestCapabilities(t *testing.T) {
	f := newOps(t, false)
	status, body := f.call(t, alice, "GET", "/api/server-operations/s1", "")
	if status != 200 || body["mutations_enabled"] != false || body["host"] != "example.test" || body["username"] != "deploy" {
		t.Fatalf("%d %v", status, body)
	}
	if w := body["write_actions"].([]any); len(w) != 0 || len(body["read_actions"].([]any)) != 6 {
		t.Fatalf("actions %v", body)
	}
	bob := principal.Principal{UserID: 2, SessionID: "auth-b"}
	status, body = f.call(t, bob, "GET", "/api/server-operations/s1", "")
	wantCode(t, status, body, 404, "unavailable")
	status, body = f.call(t, principal.Principal{}, "GET", "/api/server-operations/s1", "")
	wantCode(t, status, body, 401, "authentication_required")
	f = newOps(t, true)
	_, body = f.call(t, alice, "GET", "/api/server-operations/s1", "")
	if body["mutations_enabled"] != true || len(body["write_actions"].([]any)) != 8 {
		t.Fatalf("enabled %v", body)
	}
}

func TestReadRunsTheFixedCommandOnly(t *testing.T) {
	f := newOps(t, false) // reads do not need the switch
	f.exec.answer = func(line, stdin string) (string, string, int, error) {
		switch {
		case strings.HasPrefix(line, "env LC_ALL=C ps"):
			return "    1 root 0.0 0.1 systemd\n  9 www 1.5 2.0 nginx: worker\n", "", 0, nil
		case strings.HasPrefix(line, "docker logs"):
			return "2026-11-26T10:00:00.000000000Z old\n", "2026-11-26T10:00:01.000000000Z new\n", 0, nil
		}
		return "out\x1b[31m\n", "warn\x00", 3, nil
	}
	status, body := f.call(t, alice, "POST", "/api/server-operations/read", `{"session_id":"s1","action":"process.list","target":{}}`)
	if status != 200 || body["status"] != "completed" || body["output"] != "" || len(body["processes"].([]any)) != 2 {
		t.Fatalf("%d %v", status, body)
	}
	_, body = f.call(t, alice, "POST", "/api/server-operations/read", `{"session_id":"s1","action":"container.logs","target":{"container":"`+strings.Repeat("a", 64)+`"}}`)
	if body["output"] != "2026-11-26T10:00:01.000000000Z new\n2026-11-26T10:00:00.000000000Z old" || body["error_output"] != "" {
		t.Fatalf("logs %v", body)
	}
	_, body = f.call(t, alice, "POST", "/api/server-operations/read", `{"session_id":"s1","action":"service.logs","target":{"unit":"ssh.service"},"use_sudo":true}`)
	if body["status"] != "failed" || body["exit_status"] != float64(3) || body["output"] != "out[31m\n" || body["error_output"] != "warn" {
		t.Fatalf("failed read %v", body)
	}
	if status, _ := f.call(t, alice, "POST", "/api/server-operations/read", `{"session_id":"s1","action":"process.inspect","target":{"pid":4321}}`); status != 200 {
		t.Fatalf("inspect %d", status)
	}
	calls := f.exec.calls()
	if got := calls[len(calls)-1]; got != "python3 - 4321" || !strings.Contains(f.exec.stdins[len(calls)-1], "pidfd_open") {
		t.Fatalf("inspect line %q", got)
	}
	if !slices.Contains(calls, "sudo -n -- journalctl --no-pager --reverse --lines=100 --output=short-iso --unit=ssh.service") {
		t.Fatalf("calls %q", calls)
	}
	for _, bad := range []struct{ body, code string }{
		{`[]`, "invalid_request"},
		{`not json`, "invalid_request"},
		{`{"session_id":"s1","action":"service.restart","target":{"unit":"a.service"}}`, "invalid_action"},
		{`{"session_id":"s1","action":"service.logs","target":{"unit":"a;id.service"}}`, "invalid_target"},
		{`{"session_id":"s1","action":"service.logs","target":"x"}`, "invalid_target"},
		{`{"session_id":"s1","action":"system.inspect","use_sudo":1}`, "invalid_target"},
	} {
		status, body := f.call(t, alice, "POST", "/api/server-operations/read", bad.body)
		wantCode(t, status, body, 400, bad.code)
	}
	status, body = f.call(t, alice, "POST", "/api/server-operations/read", `{"session_id":"gone","action":"system.inspect"}`)
	wantCode(t, status, body, 404, "unavailable")
	status, body = f.call(t, alice, "POST", "/api/server-operations/read", `{"session_id":5,"action":"system.inspect"}`)
	wantCode(t, status, body, 404, "unavailable")
}

func TestReadFailures(t *testing.T) {
	f := newOps(t, false)
	f.exec.answer = func(string, string) (string, string, int, error) {
		return strings.Repeat("a", opMaxOutput/2), strings.Repeat("b", opMaxOutput/2+1), 0, nil
	}
	read := `{"session_id":"s1","action":"system.inspect"}`
	status, body := f.call(t, alice, "POST", "/api/server-operations/read", read)
	wantCode(t, status, body, 413, "output_limit")
	f.exec.answer = func(string, string) (string, string, int, error) { return "", "", -1, client.ErrNoExitStatus }
	status, body = f.call(t, alice, "POST", "/api/server-operations/read", read)
	wantCode(t, status, body, 404, "unavailable")
	f.exec.answer = func(string, string) (string, string, int, error) { return "x 1 2 3\n", "", 0, nil }
	status, body = f.call(t, alice, "POST", "/api/server-operations/read", `{"session_id":"s1","action":"process.list"}`)
	wantCode(t, status, body, 400, "invalid_output")
}

func TestOneCommandPerSessionAndRevocationStopsIt(t *testing.T) {
	f := newOps(t, false)
	f.exec.release = make(chan struct{})
	read := `{"session_id":"s1","action":"system.inspect"}`
	var wg sync.WaitGroup
	var status int
	var body map[string]any
	wg.Go(func() { status, body = f.call(t, alice, "POST", "/api/server-operations/read", read) })
	waitFor(t, func() bool { return len(f.exec.calls()) == 1 })
	s2, b2 := f.call(t, alice, "POST", "/api/server-operations/read", read)
	wantCode(t, s2, b2, 429, "busy")
	f.ops.Revoked(principal.Revocation{UserID: 1, SessionID: "other"})
	f.ops.Revoked(principal.Revocation{UserID: 1, SessionID: "auth-a"})
	wg.Wait()
	wantCode(t, status, body, 404, "unavailable")
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func prepare(t *testing.T, f *opsFixture, p principal.Principal, body string) map[string]any {
	t.Helper()
	status, out := f.call(t, p, "POST", "/api/server-operations/intents", body)
	if status != 200 {
		t.Fatalf("prepare: %d %v", status, out)
	}
	return out
}

func TestWriteNeedsSwitchIntentConfirmationAndStepUp(t *testing.T) {
	f := newOps(t, false)
	status, body := f.call(t, alice, "POST", "/api/server-operations/intents", `{"session_id":"s1","action":"system.reboot"}`)
	wantCode(t, status, body, 403, "disabled")
	status, body = f.call(t, alice, "POST", "/api/server-operations/execute", `{"intent":"x"}`)
	wantCode(t, status, body, 403, "disabled")

	f = newOps(t, true)
	status, body = f.call(t, alice, "POST", "/api/server-operations/intents", `{"session_id":"s1","action":"system.inspect"}`)
	wantCode(t, status, body, 400, "invalid_action")
	in := prepare(t, f, alice, `{"session_id":"s1","action":"system.reboot"}`)
	token := in["intent"].(string)
	if in["command"] != "systemctl reboot" || in["confirmation"] != "example.test" || in["expires_in"] != float64(90) || len(token) != 43 {
		t.Fatalf("intent %v", in)
	}
	exec := func(body string, header ...string) (int, map[string]any) {
		return f.call(t, alice, "POST", "/api/server-operations/execute", body, header...)
	}
	status, body = exec(`{"intent":"` + token + `","confirmation":"wrong"}`)
	wantCode(t, status, body, 400, "confirmation_required")
	status, body = exec(`{"intent":"` + token + `","confirmation":"example.test"}`)
	if status != 403 || body["code"] != "step_up_required" || body["error"] != "Reauthentication is required." {
		t.Fatalf("no grant: %d %v", status, body)
	}
	// Another user or sign-in cannot use the intent.
	other := principal.Principal{UserID: 1, SessionID: "auth-other"}
	status, body = f.call(t, other, "POST", "/api/server-operations/execute", `{"intent":"`+token+`","confirmation":"example.test"}`, StepUpHeader, "ok")
	wantCode(t, status, body, 409, "invalid_intent")
	if len(f.exec.calls()) != 0 {
		t.Fatal("ran before the step-up")
	}
	f.exec.answer = func(string, string) (string, string, int, error) { return "", "", 0, nil }
	status, body = exec(`{"intent":"`+token+`","confirmation":"example.test"}`, StepUpHeader, "ok")
	if status != 200 || body["status"] != "requested" {
		t.Fatalf("reboot: %d %v", status, body)
	}
	if got := f.stepup.calls[len(f.stepup.calls)-1]; got != "server.operation "+token+" ok" {
		t.Fatalf("step-up %q", got)
	}
	status, body = exec(`{"intent":"`+token+`","confirmation":"example.test"}`, StepUpHeader, "ok")
	wantCode(t, status, body, 409, "invalid_intent")
	if want := []string{
		"SERVER_OPERATION_REQUESTED action=system.reboot session_id=s1 user=alice",
		"SERVER_OPERATION_RESULT action=system.reboot outcome=requested user=alice",
	}; !slices.Equal(f.audit.events, want) {
		t.Fatalf("audit %q", f.audit.events)
	}
	if got := f.exec.calls(); !slices.Equal(got, []string{"systemctl reboot"}) {
		t.Fatalf("ran %q", got)
	}
}

func TestWriteOutcomeUnknownIsNeverRetried(t *testing.T) {
	f := newOps(t, true)
	in := prepare(t, f, alice, `{"session_id":"s1","action":"service.restart","target":{"unit":"nginx.service"},"use_sudo":true}`)
	if in["command"] != "sudo -n -- systemctl restart -- nginx.service" || in["confirmation"] != "" {
		t.Fatalf("intent %v", in)
	}
	f.exec.answer = func(string, string) (string, string, int, error) { return "", "", -1, client.ErrNoExitStatus }
	status, body := f.call(t, alice, "POST", "/api/server-operations/execute", `{"intent":"`+in["intent"].(string)+`"}`, StepUpHeader, "ok")
	wantCode(t, status, body, 409, "unknown")
	if f.audit.events[1] != "SERVER_OPERATION_RESULT action=service.restart outcome=unknown user=alice" {
		t.Fatalf("audit %q", f.audit.events)
	}
}

func TestIntentIsBoundToTheSession(t *testing.T) {
	f := newOps(t, true)
	in := prepare(t, f, alice, `{"session_id":"s1","action":"process.terminate","target":{"pid":77,"start_time":"12345"}}`)
	if !strings.HasPrefix(in["command"].(string), "python3 - 77 12345 <<'EOF'\nimport os,signal,sys\n") || !strings.HasSuffix(in["command"].(string), "\nEOF") {
		t.Fatalf("review text %q", in["command"])
	}
	// The session is replaced by another with the same ID.
	f.sessions.add(1, "s1", Live{Exec: f.exec, Host: "example.test"})
	status, body := f.call(t, alice, "POST", "/api/server-operations/execute", `{"intent":"`+in["intent"].(string)+`"}`, StepUpHeader, "ok")
	wantCode(t, status, body, 404, "unavailable")
	if len(f.stepup.calls) != 0 || len(f.exec.calls()) != 0 {
		t.Fatal("a replaced session consumed the grant or ran")
	}
	for _, bad := range []string{`{"intent":5}`, `{"intent":"short"}`, `{}`} {
		status, body := f.call(t, alice, "POST", "/api/server-operations/execute", bad)
		wantCode(t, status, body, 409, "invalid_intent")
	}
}

func TestIntentLimitsAndExpiry(t *testing.T) {
	f := newOps(t, true)
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	f.ops.now = func() time.Time { return now }
	body := `{"session_id":"s1","action":"system.reboot"}`
	var first string
	for i := range maxIntentsOfUser {
		in := prepare(t, f, alice, body)
		if i == 0 {
			first = in["intent"].(string)
		}
	}
	status, out := f.call(t, alice, "POST", "/api/server-operations/intents", body)
	wantCode(t, status, out, 429, "busy")
	now = now.Add(intentTTL)
	status, out = f.call(t, alice, "POST", "/api/server-operations/execute", `{"intent":"`+first+`","confirmation":"example.test"}`, StepUpHeader, "ok")
	wantCode(t, status, out, 409, "invalid_intent")
	prepare(t, f, alice, body) // expired intents are dropped
}

func TestStepUpRefusalKeepsTheIntent(t *testing.T) {
	f := newOps(t, true)
	in := prepare(t, f, alice, `{"session_id":"s1","action":"container.stop","target":{"container":"`+strings.Repeat("f", 64)+`"}}`)
	if in["command"] != "docker stop --time 10 -- "+strings.Repeat("f", 64) {
		t.Fatalf("command %v", in["command"])
	}
	f.stepup.refused = true
	req := `{"intent":"` + in["intent"].(string) + `"}`
	status, body := f.call(t, alice, "POST", "/api/server-operations/execute", req, StepUpHeader, "ok")
	wantCode(t, status, body, 403, "step_up_required")
	f.stepup.refused = false
	status, body = f.call(t, alice, "POST", "/api/server-operations/execute", req, StepUpHeader, "ok")
	if status != 200 || body["status"] != "completed" {
		t.Fatalf("%d %v", status, body)
	}
}

func TestOversizedBodyIsRefused(t *testing.T) {
	f := newOps(t, false)
	big := `{"session_id":"s1","action":"system.inspect","pad":"` + string(bytes.Repeat([]byte("x"), maxOperationBody)) + `"}`
	status, body := f.call(t, alice, "POST", "/api/server-operations/read", big)
	wantCode(t, status, body, 400, "invalid_request")
}
