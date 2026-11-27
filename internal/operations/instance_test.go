package operations

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type fakeConns struct {
	live   []LiveConnection
	closed []string
	err    error
}

func (f *fakeConns) Live() []LiveConnection { return append([]LiveConnection(nil), f.live...) }
func (f *fakeConns) Disconnect(_ context.Context, id string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	f.closed = append(f.closed, id)
	return true, nil
}
func (f *fakeConns) SocketStats() SocketStats {
	return SocketStats{Active: len(f.live), Limit: 1024, PerUserLimit: 32, RejectedTotal: 2, RejectedPerUser: 1}
}

type fakeSessions struct {
	live   []LiveSession
	closed []string
	err    error
}

func (f *fakeSessions) Live() (int, []LiveSession) { return len(f.live), f.live }
func (f *fakeSessions) Disconnect(_ context.Context, id string) error {
	if f.err != nil {
		return f.err
	}
	f.closed = append(f.closed, id)
	return nil
}

// fakeTransfers stands in for the transfer manager of internal/transfer.
type fakeTransfers struct {
	live []LiveTransfer
	err  error
}

func (f *fakeTransfers) Live() []LiveTransfer { return f.live }
func (f *fakeTransfers) Cancel(_ context.Context, id string) (bool, string, error) {
	if f.err != nil {
		return false, "", f.err
	}
	for i, t := range f.live {
		if t.ID == id {
			f.live[i].State = "cancelling"
			return true, "cancelling", nil
		}
	}
	return false, "unavailable", nil
}

type names map[int64]string

func (n names) Usernames(_ context.Context, ids []int64) (map[int64]string, error) {
	out := map[int64]string{}
	for _, id := range ids {
		if v, ok := n[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

type fixture struct {
	h       *InstanceHTTP
	mux     *http.ServeMux
	steps   *principaltest.StepUp
	conns   *fakeConns
	ssh     *fakeSessions
	xfer    *fakeTransfers
	audit   *auditLog
	admin   principal.Principal
	created time.Time
}

func newInstance(t *testing.T) *fixture {
	t.Helper()
	at := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	f := &fixture{steps: &principaltest.StepUp{}, audit: &auditLog{}, admin: principaltest.Admin(1), created: at,
		conns: &fakeConns{live: []LiveConnection{{ID: "sid-b", UserID: 2, CreatedAt: at.Add(time.Second)}, {ID: "sid-a", UserID: 1, CreatedAt: at},
			{ID: "sid-orphan", UserID: 9, CreatedAt: at}}},
		ssh: &fakeSessions{live: []LiveSession{{ID: "s-1", UserID: 2, Target: "ops@edge.example:22", Tmux: true, CreatedAt: at},
			{ID: "s-2", UserID: 0, Target: "x@y:22"}}},
		xfer: &fakeTransfers{live: []LiveTransfer{{ID: "t-1", UserID: 2, Kind: "download", State: "running", CreatedAt: at.Add(-12 * time.Second)}}},
	}
	in := &Instance{Connections: f.conns, Sockets: f.conns, Sessions: f.ssh, Transfers: f.xfer,
		Jobs:  jobsFake{{Name: "ldap_session_revalidation", Running: true, LastRun: at.Add(-3 * time.Second)}, {Name: "secret", Running: false}},
		Names: names{1: "e2e_admin", 2: "e2e_user"}, Now: func() time.Time { return at }}
	f.h = &InstanceHTTP{Instance: in, StepUp: f.steps, Audit: f.audit, Enabled: true}
	f.mux = http.NewServeMux()
	f.h.Register(f.mux)
	return f
}

type jobsFake []LiveJob

func (j jobsFake) Live() []LiveJob { return j }

func (f *fixture) do(t *testing.T, p principal.Principal, method, path string, action principal.Action, target string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	if action != "" {
		f.steps.Issue(p, action, target, "grant")
		r.Header.Set(StepUpHeader, "grant")
	}
	r = r.WithContext(principal.With(r.Context(), p))
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%s: cache %q", path, w.Header().Get("Cache-Control"))
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v %s", path, err, w.Body.String())
	}
	return w.Code, out
}

func TestInstanceStatus(t *testing.T) {
	t.Parallel()
	f := newInstance(t)
	code, body := f.do(t, f.admin, http.MethodGet, "/admin/api/operations", "", "")
	if code != 200 {
		t.Fatal(code, body)
	}
	raw, _ := json.Marshal(body, json.Deterministic(true))
	const want = `{"jobs":{"accepting_work":true,"cancelling":0,"queued":0,"running":1,"workers":2},"maintenance":false,` +
		`"sessions":{"active":2,"tmux":1,"users":1},"sockets":{"active":3,"http_reserve":0,"limit":1024,"per_user_limit":32,` +
		`"rejected_per_user":1,"rejected_total":2},"transfers":{"cancelling":0,"pending":0,"running":1}}`
	if string(raw) != want {
		t.Errorf("status\n got %s\nwant %s", raw, want)
	}
	if strings.Contains(string(raw), "sid-") || strings.Contains(string(raw), "edge.example") {
		t.Error("status leaks ids or targets")
	}
}

func TestInstanceDetails(t *testing.T) {
	t.Parallel()
	f := newInstance(t)
	code, body := f.do(t, f.admin, http.MethodGet, "/admin/api/operations/details", "", "")
	if code != 200 {
		t.Fatal(code, body)
	}
	raw, _ := json.Marshal(body, json.Deterministic(true))
	s := string(raw)
	for _, want := range []string{
		`"connections":{"items":[{"created_at":"2026-11-27T08:00:00Z","id":"` + ConnectionRef("sid-a") + `","username":"e2e_admin"},` +
			`{"created_at":"2026-11-27T08:00:01Z","id":"` + ConnectionRef("sid-b") + `","username":"e2e_user"}],"total":2}`,
		`{"created_at":"2026-11-27T08:00:00Z","id":"` + SessionRef("s-1") + `","target":"ops@edge.example:22","tmux":true,"username":"e2e_user"}`,
		`{"created_at":null,"id":"` + SessionRef("s-2") + `","target":"x@y:22","tmux":false,"username":null}`,
		`"transfers":{"items":[{"age_seconds":12,"direction":"download","id":"t-1","state":"running","username":"e2e_user"}],"total":1}`,
		`"jobs":{"items":[{"age_seconds":3,"cancelling":false,"kind":"maintenance","state":"running"}],"total":1}`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("details miss %s\nin %s", want, s)
		}
	}
	for _, leak := range []string{`"sid-a"`, `"s-1"`, "secret", "sid-orphan"} {
		if strings.Contains(s, leak) {
			t.Errorf("details leak %s", leak)
		}
	}
}

func TestInstanceAccess(t *testing.T) {
	t.Parallel()
	f := newInstance(t)
	for _, path := range []string{"/admin/api/operations", "/admin/api/operations/details"} {
		if code, _ := f.do(t, principaltest.User(2), http.MethodGet, path, "", ""); code != 403 {
			t.Errorf("non-admin %s %d", path, code)
		}
	}
	ref := ConnectionRef("sid-b")
	if code, _ := f.do(t, principaltest.User(2), http.MethodPost, "/admin/api/operations/connections/"+ref+"/disconnect",
		principal.ActionOperationsConnectionDisconnect, ref); code != 403 {
		t.Errorf("non-admin disconnect %d", code)
	}
	// A grant for another reference or action is refused and nothing ends.
	code, body := f.do(t, f.admin, http.MethodPost, "/admin/api/operations/connections/"+ref+"/disconnect",
		principal.ActionOperationsConnectionDisconnect, ConnectionRef("sid-a"))
	if code != 403 || body["code"] != "step_up_required" || len(f.conns.closed) != 0 {
		t.Errorf("foreign grant %d %v %v", code, body, f.conns.closed)
	}
	code, _ = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/sessions/"+SessionRef("s-1")+"/disconnect",
		principal.ActionOperationsTransferCancel, SessionRef("s-1"))
	if code != 403 || len(f.ssh.closed) != 0 {
		t.Errorf("wrong action %d", code)
	}
	f.h.Enabled = false
	r := httptest.NewRequest(http.MethodGet, "/admin/api/operations", nil)
	r = r.WithContext(principal.With(r.Context(), f.admin))
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("disabled %d", w.Code)
	}
}

func TestInstanceActions(t *testing.T) {
	t.Parallel()
	f := newInstance(t)
	ref := ConnectionRef("sid-b")
	code, body := f.do(t, f.admin, http.MethodPost, "/admin/api/operations/connections/"+ref+"/disconnect",
		principal.ActionOperationsConnectionDisconnect, ref)
	if code != 200 || body["state"] != "disconnected" || len(f.conns.closed) != 1 || f.conns.closed[0] != "sid-b" {
		t.Errorf("disconnect %d %v %v", code, body, f.conns.closed)
	}
	gone := ConnectionRef("missing")
	code, body = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/connections/"+gone+"/disconnect",
		principal.ActionOperationsConnectionDisconnect, gone)
	if code != 404 || body["code"] != "unavailable" {
		t.Errorf("gone connection %d %v", code, body)
	}
	sref := SessionRef("s-1")
	code, body = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/sessions/"+sref+"/disconnect",
		principal.ActionOperationsSessionDisconnect, sref)
	if code != 200 || body["state"] != "disconnected" || f.ssh.closed[0] != "s-1" {
		t.Errorf("ssh disconnect %d %v", code, body)
	}
	// A session without an owner is not offered for disconnection.
	oref := SessionRef("s-2")
	if code, _ = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/sessions/"+oref+"/disconnect",
		principal.ActionOperationsSessionDisconnect, oref); code != 404 {
		t.Errorf("ownerless session %d", code)
	}
	code, body = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/transfers/t-1/cancel", principal.ActionOperationsTransferCancel, "t-1")
	if code != 200 || body["state"] != "cancelling" || body["accepted"] != true {
		t.Errorf("cancel %d %v", code, body)
	}
	code, body = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/transfers/t-9/cancel", principal.ActionOperationsTransferCancel, "t-9")
	if code != 404 || body["state"] != "unavailable" || body["accepted"] != false {
		t.Errorf("cancel gone %d %v", code, body)
	}
	f.conns.err, f.ssh.err, f.xfer.err = errors.New("boom"), errors.New("boom"), errors.New("boom")
	ref = ConnectionRef("sid-a")
	if code, body = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/connections/"+ref+"/disconnect",
		principal.ActionOperationsConnectionDisconnect, ref); code != 503 || body["code"] != "action_unconfirmed" {
		t.Errorf("unconfirmed %d %v", code, body)
	}
	if code, body = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/sessions/"+sref+"/disconnect",
		principal.ActionOperationsSessionDisconnect, sref); code != 503 || strings.Contains(body["error"].(string), "boom") {
		t.Errorf("ssh unconfirmed %d %v", code, body)
	}
	if code, _ = f.do(t, f.admin, http.MethodPost, "/admin/api/operations/transfers/t-1/cancel", principal.ActionOperationsTransferCancel, "t-1"); code != 503 {
		t.Errorf("cancel unconfirmed %d", code)
	}
	want := []string{"ADMIN_CONNECTION_DISCONNECT", "ADMIN_SSH_DISCONNECT", "ADMIN_TRANSFER_CANCEL",
		"ADMIN_TRANSFER_CANCEL", "ADMIN_CONNECTION_DISCONNECT_FAILED", "ADMIN_SSH_DISCONNECT_FAILED", "ADMIN_TRANSFER_CANCEL_FAILED"}
	if strings.Join(f.audit.events, ",") != strings.Join(want, ",") {
		t.Errorf("audit %v", f.audit.events)
	}
}
