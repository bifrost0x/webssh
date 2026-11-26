package hostkey

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type fixedTargets []Target

func (f fixedTargets) SSHTargets(context.Context, int64) ([]Target, error) { return f, nil }

type httpFixture struct {
	mux    *http.ServeMux
	stepUp *principaltest.StepUp
	store  *Store
	user   principal.Principal
	ids    []string
}

func newHTTPFixture(t *testing.T, enabled bool) *httpFixture {
	t.Helper()
	s, db := newStore(t)
	k := newKey(t)
	importRaw(t, db, ScopeUser, 1, "a.test "+k.Type()+" "+lineKey(k)+"\n[b.test]:2222 "+k.Type()+" "+lineKey(k)+"\n")
	f := &httpFixture{mux: http.NewServeMux(), stepUp: &principaltest.StepUp{}, store: s, user: principaltest.User(1)}
	(&HTTP{Store: s, Targets: fixedTargets{{ID: "p1", Name: "A", Kind: "ssh", Host: "a.test"}}, StepUp: f.stepUp, Enabled: enabled}).Register(f.mux)
	entries, err := s.List(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		f.ids = append(f.ids, e.ID)
	}
	return f
}

func (f *httpFixture) do(t *testing.T, p *principal.Principal, method, path string, header map[string]string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	if p != nil {
		req = req.WithContext(principal.With(req.Context(), *p))
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Type") == "application/json" {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func TestHTTPListShape(t *testing.T) {
	f := newHTTPFixture(t, true)
	status, body := f.do(t, &f.user, "GET", "/api/host-keys", nil)
	entries, _ := body["entries"].([]any)
	if status != 200 || len(entries) != 2 {
		t.Fatalf("%d %v", status, body)
	}
	e := entries[1].(map[string]any)
	if e["host"] != "b.test" || e["port"] != 2222.0 || e["marker"] != nil || e["scope"] != "user" || e["owner_id"] != 1.0 || e["id"] != f.ids[1] {
		t.Fatalf("entry %v", e)
	}
	status, body = f.do(t, &f.user, "GET", "/api/host-keys/effective", nil)
	if targets, _ := body["targets"].([]any); status != 200 || len(targets) != 1 {
		t.Fatalf("%d %v", status, body)
	}
}

func TestHTTPRequiresAuthAndFeature(t *testing.T) {
	f := newHTTPFixture(t, true)
	if status, body := f.do(t, nil, "GET", "/api/host-keys", nil); status != 401 || body["code"] != "authentication_required" || body["success"] != false {
		t.Fatalf("anonymous: %d %v", status, body)
	}
	recovery := f.user
	recovery.Recovery = true
	if status, _ := f.do(t, &recovery, "GET", "/api/host-keys", nil); status != 403 {
		t.Fatalf("recovery session: %d", status)
	}
	off := newHTTPFixture(t, false)
	for _, path := range []string{"/api/host-keys", "/api/host-keys/effective", "/api/host-keys/" + off.ids[0] + "/deletion-impact"} {
		if status, _ := off.do(t, &off.user, "GET", path, nil); status != 404 {
			t.Errorf("%s with management off: %d", path, status)
		}
	}
}

// Deleting trust is a step-up action bound to the entry. The grant is spent
// only when the entry exists and the previewed revision still holds.
func TestHTTPDeleteNeedsStepUp(t *testing.T) {
	f := newHTTPFixture(t, true)
	path := "/api/host-keys/" + f.ids[0]
	status, impact := f.do(t, &f.user, "GET", path+"/deletion-impact", nil)
	revision, _ := impact["revision"].(string)
	if status != 200 || len(revision) != 64 {
		t.Fatalf("impact %d %v", status, impact)
	}
	if status, body := f.do(t, &f.user, "DELETE", path, map[string]string{"If-Match": revision}); status != 403 || body["code"] != "step_up_required" {
		t.Fatalf("without grant: %d %v", status, body)
	}
	f.stepUp.Issue(f.user, principal.ActionHostKeyDelete, f.ids[1], "g-other")
	if status, _ := f.do(t, &f.user, "DELETE", path, map[string]string{"If-Match": revision, StepUpHeader: "g-other"}); status != 403 {
		t.Fatalf("grant for another entry: %d", status)
	}
	f.stepUp.Issue(f.user, principal.ActionHostKeyDelete, f.ids[0], "g1")
	// Ids and revisions come from per-run keys; the altered values differ
	// from the real ones whatever their digits are.
	stale := "0" + revision[1:]
	if stale == revision {
		stale = "1" + revision[1:]
	}
	if status, body := f.do(t, &f.user, "DELETE", path, map[string]string{"If-Match": stale, StepUpHeader: "g1"}); status != 412 || body["code"] != "precondition_failed" {
		t.Fatalf("stale revision: %d %v", status, body)
	}
	unknown := f.ids[0][:63] + "0"
	if unknown == f.ids[0] {
		unknown = f.ids[0][:63] + "1"
	}
	if status, body := f.do(t, &f.user, "DELETE", "/api/host-keys/"+unknown, map[string]string{StepUpHeader: "g1"}); status != 404 {
		t.Fatalf("unknown entry: %d %v", status, body)
	}
	if status, body := f.do(t, &f.user, "DELETE", path, map[string]string{"If-Match": revision, StepUpHeader: "g1"}); status != 200 || body["ok"] != true {
		t.Fatalf("delete: %d %v", status, body)
	}
	if entries, _ := f.store.List(t.Context(), 1); len(entries) != 1 || entries[0].ID != f.ids[1] {
		t.Fatalf("remaining %+v", entries)
	}
	other := principaltest.User(2)
	f.stepUp.Issue(other, principal.ActionHostKeyDelete, f.ids[1], "g2")
	if status, _ := f.do(t, &other, "DELETE", "/api/host-keys/"+f.ids[1], map[string]string{StepUpHeader: "g2"}); status != 404 {
		t.Fatalf("another user's entry: %d", status)
	}
	for _, c := range f.stepUp.Calls() {
		if c.Grant == "g1" && c.Err != nil {
			t.Fatalf("the valid grant was offered before the checks passed: %+v", c)
		}
	}
}

// decimalValue assumes every range of Unicode Nd is a run of whole blocks
// of ten digits.
func TestDecimalTable(t *testing.T) {
	for _, r := range unicode.Nd.R16 {
		if r.Stride != 1 || (int(r.Hi)-int(r.Lo)+1)%10 != 0 {
			t.Errorf("range %+v", r)
		}
	}
	for _, r := range unicode.Nd.R32 {
		if r.Stride != 1 || (int(r.Hi)-int(r.Lo)+1)%10 != 0 {
			t.Errorf("range %+v", r)
		}
	}
}

// An error body carries only what fault.Status allows, never the cause.
func TestHTTPErrorBodyHasNoCause(t *testing.T) {
	f := newHTTPFixture(t, true)
	f.mux = http.NewServeMux()
	(&HTTP{Store: f.store, Targets: failingTargets{}, StepUp: f.stepUp, Enabled: true}).Register(f.mux)
	status, body := f.do(t, &f.user, "GET", "/api/host-keys/effective", nil)
	if msg, _ := body["error"].(string); status != 500 || body["code"] != "storage_error" || strings.Contains(msg, "SECRET-CAUSE") {
		t.Fatalf("%d %v", status, body)
	}
}

type failingTargets struct{}

func (failingTargets) SSHTargets(context.Context, int64) ([]Target, error) {
	return nil, fault.Wrap(fault.StorageError, errors.New("SECRET-CAUSE /var/lib/x"), "")
}
