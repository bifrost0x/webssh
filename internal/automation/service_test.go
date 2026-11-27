package automation

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

type client_ struct {
	t     *testing.T
	mux   *http.ServeMux
	p     principal.Principal
	https bool
	svc   *Service
	steps *principaltest.StepUp
}

func newClient(t *testing.T, w *world) *client_ {
	t.Helper()
	svc, steps := newService(t, w)
	c := &client_{t: t, mux: http.NewServeMux(), p: principaltest.User(owner), https: true, svc: svc, steps: steps}
	(&HTTP{Service: svc, HTTPS: func(*http.Request) bool { return c.https },
		Index: func(*http.Request) string { return "/" }}).Register(c.mux)
	return c
}

func (c *client_) do(method, path, body string, header ...string) (int, map[string]any, string) {
	c.t.Helper()
	r := httptest.NewRequest(method, "http://webssh.test"+path, strings.NewReader(body))
	if c.p.UserID != 0 {
		r = r.WithContext(principal.With(r.Context(), c.p))
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	c.mux.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Body.String()
}

const book = `{"name":"Check","steps":[{"name":"one","command":"first"},{"name":"two","command":"second","sudo":true}]}`

func (c *client_) saveBook(body string) string {
	c.t.Helper()
	code, out, raw := c.do("POST", "/api/automation/runbooks", body)
	if code != 200 {
		c.t.Fatalf("save: %d %s", code, raw)
	}
	return out["runbook"].(map[string]any)["id"].(string)
}

func (c *client_) preview(id string, targets ...string) (int, map[string]any) {
	c.t.Helper()
	b, _ := json.Marshal(map[string]any{"runbook_id": id, "profile_ids": targets})
	code, out, _ := c.do("POST", "/api/automation/preview", string(b))
	return code, out
}

// start confirms the review with a fresh grant.
func (c *client_) start(intent, confirmation string) (int, map[string]any) {
	c.t.Helper()
	grant := "grant-" + intent[:6]
	c.steps.Issue(c.p, principal.ActionAutomationRun, intent, grant)
	b, _ := json.Marshal(map[string]any{"intent": intent, "confirmation": confirmation})
	code, out, _ := c.do("POST", "/api/automation/start", string(b), StepUpHeader, grant)
	return code, out
}

func (c *client_) waitRun(id string) map[string]any {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, out, _ := c.do("GET", "/api/automation/runs", "")
		for _, r := range out["runs"].([]any) {
			run := r.(map[string]any)
			if run["id"] == id && terminal(run["status"].(string)) {
				return run
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.t.Fatalf("run %s did not finish", id)
	return nil
}

func TestRunThroughJumpHostWithSavedPassword(t *testing.T) {
	t.Parallel()
	w := newWorld()
	c := newClient(t, w)
	id := c.saveBook(book)
	code, review := c.preview(id, "p2")
	if code != 200 || review["confirmation"] != "1" {
		t.Fatalf("preview: %d %v", code, review)
	}
	intent := review["intent"].(string)
	if code, out := c.start(intent, "2"); code != 400 || out["code"] != "confirmation_required" {
		t.Fatalf("wrong confirmation: %d %v", code, out)
	}
	if len(c.steps.Calls()) != 0 {
		t.Fatal("a wrong confirmation consumed the grant")
	}
	b, _ := json.Marshal(map[string]any{"intent": intent, "confirmation": "1"})
	if code, out, _ := c.do("POST", "/api/automation/start", string(b)); code != 403 || out["code"] != "step_up_required" {
		t.Fatalf("without grant: %d %v", code, out)
	}
	code, out := c.start(intent, "1")
	if code != http.StatusAccepted {
		t.Fatalf("start: %d %v", code, out)
	}
	run := c.waitRun(out["run"].(map[string]any)["id"].(string))
	if run["status"] != "succeeded" {
		t.Fatalf("run: %v", run)
	}
	waitQuota(t, w)
	w.mu.Lock()
	if len(w.dials) != 1 || len(w.dials[0].Jumps) != 1 || w.dials[0].Hop.Auth.Password != "s3cret-pw" ||
		w.dials[0].Jumps[0].Auth.KeyID != "k1" || w.dials[0].Jumps[0].Auth.Password != "" {
		t.Fatalf("dial: %+v", w.dials)
	}
	want := []string{`sh -c 'eval "$(cat)"'|first`, `sudo -n -- sh -c 'eval "$(cat)"'|second`}
	if strings.Join(w.scripts, ";") != strings.Join(want, ";") {
		t.Fatalf("scripts %q", w.scripts)
	}
	w.mu.Unlock()
	// The intent is spent.
	if code, out := c.start(intent, "1"); code != 409 || out["code"] != "invalid_intent" {
		t.Fatalf("second start: %d %v", code, out)
	}
}

// waitQuota waits until the run gave its quotas back; the record is
// final a moment before.
func waitQuota(t *testing.T, w *world) {
	t.Helper()
	for range 500 {
		w.mu.Lock()
		n := w.quota
		w.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("quota not released")
}

// waitScript waits until a step reached the host.
func waitScript(t *testing.T, w *world) {
	t.Helper()
	for range 500 {
		w.mu.Lock()
		n := len(w.scripts)
		w.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no step started")
}

func TestHistorySizeMatchesTheFile(t *testing.T) {
	t.Parallel()
	o := readOracle(t)
	var runs []Run
	for _, c := range o.Runs {
		r, err := ParseRun(jsontext.Value(c.Stored))
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, r)
		items := make([]jsontext.Value, len(runs))
		for i := range runs {
			items[i] = runs[i].Value()
		}
		doc := pyjson.Object([]pyjson.Member{{Name: "version", Value: jsontext.Value("1")}, {Name: "runs", Value: pyjson.Array(items)}})
		if got, want := historyBytes(runs), len(pyDump(doc, dumpOptions{indent: 2})); got != want {
			t.Fatalf("%d runs: %d bytes, the file has %d", len(runs), got, want)
		}
	}
	if historyBytes(nil) != len("{\n  \"version\": 1,\n  \"runs\": []\n}") {
		t.Fatal("empty history")
	}
}

func TestReviewRefusals(t *testing.T) {
	t.Parallel()
	w := newWorld()
	c := newClient(t, w)
	id := c.saveBook(book)
	for _, tc := range []struct {
		targets []string
		change  func(*world)
		code    string
	}{
		{[]string{"nope"}, nil, "invalid_targets"},
		{[]string{"p3"}, nil, "unsupported_target"},
		{[]string{"p1"}, func(w *world) { delete(w.trusted, "web.test:22") }, "host_key_required"},
		{[]string{"p2"}, func(w *world) { delete(w.bindings, "p2") }, "credential_missing"},
		{[]string{"p1"}, func(w *world) { delete(w.keys, "k1") }, "key_unavailable"},
	} {
		w2 := newWorld()
		if tc.change != nil {
			tc.change(w2)
		}
		c2 := newClient(t, w2)
		id2 := c2.saveBook(book)
		code, out := c2.preview(id2, tc.targets...)
		if out["code"] != tc.code || code == 200 {
			t.Errorf("%v: %d %v, want %s", tc.targets, code, out, tc.code)
		}
		if tc.code == "host_key_required" && (code != 409 || out["hosts"].([]any)[0] != "Web") {
			t.Errorf("host key refusal %d %v", code, out)
		}
	}
	if code, out := c.preview("missing", "p1"); code != 404 || out["code"] != "not_found" {
		t.Errorf("missing runbook: %d %v", code, out)
	}
	// A group selects its supported members.
	b, _ := json.Marshal(map[string]any{"runbook_id": id, "groups": []string{"Lab"}})
	if code, out, raw := c.do("POST", "/api/automation/preview", string(b)); code != 200 || out["confirmation"] != "2" {
		t.Errorf("group: %d %s", code, raw)
	}
}

// A change after the review stops the start: the runbook, the host, the
// key or the password binding.
func TestStartRefusesChangedReview(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(c *client_, w *world, id string){
		"runbook": func(c *client_, _ *world, id string) {
			c.saveBook(`{"id":"` + id + `","name":"Check","steps":[{"name":"one","command":"other"}]}`)
		},
		"host": func(_ *client_, w *world, _ string) {
			w.set(func(w *world) { w.profiles[1] = strings.Replace(w.profiles[1], "db.test", "evil.test", 1) })
		},
		"key":      func(_ *client_, w *world, _ string) { w.set(func(w *world) { w.keys["k1"] = []byte("other") }) },
		"password": func(_ *client_, w *world, _ string) { w.set(func(w *world) { w.bindings["p2"] = "gen-2" }) },
		"switch":   func(_ *client_, w *world, _ string) { w.set(func(w *world) { w.enabled = false }) },
	} {
		w := newWorld()
		c := newClient(t, w)
		id := c.saveBook(book)
		_, review := c.preview(id, "p2")
		change(c, w, id)
		code, out := c.start(review["intent"].(string), "1")
		want := "preview_changed"
		if name == "switch" {
			want = "disabled"
		}
		if out["code"] != want {
			t.Errorf("%s: %d %v", name, code, out)
		}
		if len(w.dials) != 0 {
			t.Errorf("%s: dialled after a change", name)
		}
	}
}

func TestRunOutcomes(t *testing.T) {
	t.Parallel()
	w := newWorld()
	c := newClient(t, w)
	run := func(body string, targets ...string) map[string]any {
		id := c.saveBook(body)
		code, review := c.preview(id, targets...)
		if code != 200 {
			t.Fatalf("preview %d %v", code, review)
		}
		code, out := c.start(review["intent"].(string), review["confirmation"].(string))
		if code != 202 {
			t.Fatalf("start %d %v", code, out)
		}
		return c.waitRun(out["run"].(map[string]any)["id"].(string))
	}
	failed := run(`{"name":"F","steps":[{"name":"a","command":"fail"},{"name":"b","command":"x"}]}`, "p1", "p2")
	tg := failed["targets"].([]any)
	first := tg[0].(map[string]any)
	steps := first["steps"].([]any)
	if failed["status"] != "failed" || first["status"] != "failed" || tg[1].(map[string]any)["status"] != "skipped" ||
		steps[0].(map[string]any)["reason"] != "nonzero_exit" || steps[0].(map[string]any)["stderr"] != "boom\n" ||
		steps[0].(map[string]any)["exit_code"] != float64(2) || steps[1].(map[string]any)["status"] != "skipped" {
		t.Fatalf("stop on error: %v", failed)
	}
	cont := run(`{"name":"C","stop_on_error":false,"steps":[{"name":"a","command":"fail"}]}`, "p1", "p2")
	if ts := cont["targets"].([]any); ts[1].(map[string]any)["status"] != "failed" {
		t.Fatalf("continue on error: %v", cont)
	}
	leak := run(`{"name":"L","steps":[{"name":"a","command":"leak"}]}`, "p2")
	out := leak["targets"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)["stdout"]
	if out != "pw is [redacted]\n" {
		t.Fatalf("password not redacted: %q", out)
	}
	// Export of the finished run.
	id := leak["id"].(string)
	code, _, body := c.do("GET", "/api/automation/runs/"+id+"/export?format=csv", "")
	if code != 200 || !strings.HasPrefix(body, "run_id,workflow,") || strings.Contains(body, "s3cret") {
		t.Fatalf("csv export %d %q", code, body)
	}
	code, _, body = c.do("GET", "/api/automation/runs/"+id+"/export?format=xml", "")
	if code != 400 {
		t.Fatalf("unknown format: %d %s", code, body)
	}
	code, _, body = c.do("GET", "/api/automation/runs/"+id+"/export", "")
	if code != 200 || !strings.HasPrefix(body, `{"id": "`) {
		t.Fatalf("json export %d %s", code, body)
	}
}

func TestCancelAndActiveRun(t *testing.T) {
	t.Parallel()
	w := newWorld()
	c := newClient(t, w)
	id := c.saveBook(`{"name":"W","steps":[{"name":"a","command":"wait","timeout":60}]}`)
	_, review := c.preview(id, "p1")
	_, out := c.start(review["intent"].(string), "1")
	runID := out["run"].(map[string]any)["id"].(string)
	// One run per user.
	_, review2 := c.preview(id, "p1")
	if code, out := c.start(review2["intent"].(string), "1"); code != 429 || out["code"] != "busy" {
		t.Fatalf("second run: %d %v", code, out)
	}
	if code, out, _ := c.do("DELETE", "/api/automation/runs/"+runID, ""); code != 409 || out["code"] != "run_active" {
		t.Fatalf("delete active: %d %v", code, out)
	}
	waitScript(t, w)
	if code, _, _ := c.do("POST", "/api/automation/runs/"+runID+"/cancel", "{}"); code != 200 {
		t.Fatalf("cancel: %d", code)
	}
	run := c.waitRun(runID)
	step := run["targets"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)
	if run["status"] != "unknown" || step["status"] != "unknown" || step["reason"] != "cancelled" || step["stdout"] != "started\n" {
		t.Fatalf("cancelled run: %v", run)
	}
	waitQuota(t, w)
	if code, out, _ := c.do("DELETE", "/api/automation/runs/"+runID, ""); code != 200 || out["deleted"] != float64(1) {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, out, _ := c.do("POST", "/api/automation/runs/clear", "{}"); code != 200 || out["deleted"] != float64(0) {
		t.Fatalf("clear: %d %v", code, out)
	}
	if code, _, _ := c.do("POST", "/api/automation/runs/nope/cancel", "{}"); code != 404 {
		t.Fatalf("cancel unknown: %d", code)
	}
}

// A revoked sign-in stops its run and drops its reviews.
func TestRevocationStopsRun(t *testing.T) {
	t.Parallel()
	w := newWorld()
	c := newClient(t, w)
	id := c.saveBook(`{"name":"W","steps":[{"name":"a","command":"wait","timeout":60}]}`)
	_, review := c.preview(id, "p1")
	_, pending := c.preview(id, "p1")
	_, out := c.start(review["intent"].(string), "1")
	waitScript(t, w)
	c.svc.Revoked(principal.Revocation{UserID: owner, SessionID: c.p.SessionID})
	run := c.waitRun(out["run"].(map[string]any)["id"].(string))
	if run["status"] != "unknown" {
		t.Fatalf("revoked run: %v", run)
	}
	if code, out := c.start(pending["intent"].(string), "1"); code != 409 || out["code"] != "invalid_intent" {
		t.Fatalf("review of a revoked sign-in: %d %v", code, out)
	}
}

func TestGates(t *testing.T) {
	t.Parallel()
	w := newWorld()
	c := newClient(t, w)
	c.https = false
	if code, out, _ := c.do("GET", "/api/automation/state", ""); code != 403 || out["code"] != "https_required" {
		t.Fatalf("http: %d %v", code, out)
	}
	c.https = true
	w.set(func(w *world) { w.enabled = false })
	if code, out, _ := c.do("GET", "/api/automation/state", ""); code != 403 || out["code"] != "disabled" {
		t.Fatalf("disabled: %d %v", code, out)
	}
	w.set(func(w *world) { w.enabled = true })
	c.p = principal.Principal{}
	if code, out, _ := c.do("GET", "/api/automation/state", ""); code != 401 || out["code"] != "authentication_required" {
		t.Fatalf("anonymous: %d %v", code, out)
	}
	c.p = principaltest.User(owner)
	code, out, raw := c.do("GET", "/api/automation/state", "")
	if code != 200 || out["enabled"] != true || len(out["profiles"].([]any)) != 3 {
		t.Fatalf("state: %d %s", code, raw)
	}
	var st struct {
		Profiles []struct {
			ID         string  `json:"id"`
			Supported  bool    `json:"supported"`
			Status     string  `json:"credential_status"`
			Via        *string `json:"via"`
			RouteState string  `json:"route_credential_status"`
			Reason     string  `json:"unsupported_reason"`
		} `json:"profiles"`
	}
	_ = json.Unmarshal([]byte(raw), &st)
	p2, p3 := st.Profiles[1], st.Profiles[2]
	if !p2.Supported || p2.Status != "ready" || p2.Via == nil || *p2.Via != "Bastion" || p2.RouteState != "ready" ||
		p3.Supported || p3.Reason == "" {
		t.Fatalf("profiles: %+v", st.Profiles)
	}
}

func TestInsecureLoopback(t *testing.T) {
	t.Parallel()
	h := &HTTP{InsecureLoopback: true}
	for _, tc := range []struct {
		remote  string
		header  string
		proxied bool
		ok      bool
	}{
		{"127.0.0.1:5000", "", false, true},
		{"[::1]:5000", "", false, true},
		{"192.168.1.2:5000", "", false, false},
		{"127.0.0.1:5000", "X-Forwarded-For", false, false},
		{"127.0.0.1:5000", "Forwarded", false, false},
		{"127.0.0.1:5000", "", true, false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.header != "" {
			r.Header.Set(tc.header, "1.2.3.4")
		}
		h.Proxied = tc.proxied
		if err := h.secure(r); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	if (&HTTP{}).secure(httptest.NewRequest("GET", "/", nil)) == nil {
		t.Error("plain HTTP accepted without the exception")
	}
}

func TestRunbookLibrary(t *testing.T) {
	t.Parallel()
	c := newClient(t, newWorld())
	a := c.saveBook(book)
	b := c.saveBook(`{"name":"Second","steps":[{"name":"x","command":"y"}]}`)
	c.saveBook(`{"id":"` + a + `","name":"First again","steps":[{"name":"x","command":"y"}]}`)
	_, out, _ := c.do("GET", "/api/automation/state", "")
	books := out["runbooks"].([]any)
	if len(books) != 2 || books[0].(map[string]any)["id"] != b || books[1].(map[string]any)["name"] != "First again" {
		t.Fatalf("library order: %v", books)
	}
	if code, out, _ := c.do("POST", "/api/automation/runbooks", `{"id":"missing","name":"x","steps":[{"name":"x","command":"y"}]}`); code != 404 || out["code"] != "not_found" {
		t.Fatalf("unknown id: %d %v", code, out)
	}
	if code, out, _ := c.do("POST", "/api/automation/runbooks", `[]`); code != 400 || out["code"] != "invalid_request" {
		t.Fatalf("not an object: %d %v", code, out)
	}
	if code, _, _ := c.do("DELETE", "/api/automation/runbooks/"+b, ""); code != 200 {
		t.Fatal("delete")
	}
	if code, _, _ := c.do("DELETE", "/api/automation/runbooks/"+b, ""); code != 404 {
		t.Fatal("delete twice")
	}
	big := strings.Repeat("x", 8000)
	var steps []string
	for range 20 {
		steps = append(steps, `{"name":"s","command":"`+big+`"}`)
	}
	body := `{"name":"Big","steps":[` + strings.Join(steps, ",") + `]}`
	var last int
	for range 8 {
		last, _, _ = c.do("POST", "/api/automation/runbooks", body)
	}
	if last != 400 {
		t.Fatalf("library above 1 MiB: %d", last)
	}
}

// The history trims by size like the Python release and recovers an
// interrupted record once.
func TestHistoryRecoveryAndTrim(t *testing.T) {
	t.Parallel()
	s, _ := newService(t, newWorld())
	ctx := t.Context()
	open := Run{ID: "r1", Name: "n", CreatedAt: "t", Status: StatusRunning, Targets: []Target{{ID: "p", Name: "n", Host: "h", Port: 22,
		Username: "u", Status: StatusRunning, Steps: []StepResult{{Name: "s", Status: StatusRunning, Duration: "0", Detailed: true}}}}}
	if err := s.persist(ctx, owner, open); err != nil {
		t.Fatal(err)
	}
	runs, err := s.History(ctx, owner)
	if err != nil || runs[0].Status != StatusUnknown || *runs[0].Targets[0].Steps[0].Reason != "run_interrupted" {
		t.Fatalf("recovered: %+v %v", runs, err)
	}
	stored, _ := s.History(ctx, owner)
	if stored[0].Status != StatusUnknown {
		t.Fatal("recovery not stored")
	}
	out := strings.Repeat("é", 4000) // 8000 bytes, escaped 24000 in the file
	for i := range 60 {
		r := open
		r.ID, r.Status = "big"+itoa(int64(i)), StatusSucceeded
		r.Targets = []Target{r.Targets[0]}
		r.Targets[0].Status = StatusSucceeded
		r.Targets[0].Steps = []StepResult{{Name: "s", Status: StatusSucceeded, Duration: "0.5", Detailed: true, Stdout: out}}
		if err := s.persist(ctx, owner, r); err != nil {
			t.Fatal(err)
		}
	}
	runs, _ = s.History(ctx, owner)
	if len(runs) >= MaxRuns || runs[0].ID != "big59" || historyBytes(runs) > MaxStoreBytes {
		t.Fatalf("history of %d runs, %d bytes", len(runs), historyBytes(runs))
	}
}
