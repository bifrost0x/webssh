package automation

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// RS8-H20: another user reaches none of the owner's runbooks and runs:
// every route with an object id answers 404 and the objects stay.
func TestOtherUserReachesNoRunbookOrRun(t *testing.T) {
	t.Parallel()
	w := newWorld()
	c := newClient(t, w)
	bookID := c.saveBook(`{"name":"Q","steps":[{"name":"a","command":"first"}]}`)
	_, review := c.preview(bookID, "p1")
	_, out := c.start(review["intent"].(string), "1")
	runID := out["run"].(map[string]any)["id"].(string)
	c.waitRun(runID)
	waitQuota(t, w)

	owner := c.p
	c.p = principaltest.User(owner.UserID + 1)
	for _, k := range []struct{ method, path, body string }{
		{"DELETE", "/api/automation/runbooks/" + bookID, ""},
		{"POST", "/api/automation/preview", `{"runbook_id":"` + bookID + `","profile_ids":["p1"]}`},
		{"POST", "/api/automation/runs/" + runID + "/cancel", "{}"},
		{"DELETE", "/api/automation/runs/" + runID, ""},
		{"GET", "/api/automation/runs/" + runID + "/export", ""},
	} {
		if code, _, raw := c.do(k.method, k.path, k.body); code != http.StatusNotFound {
			t.Errorf("%s %s: %d %s", k.method, k.path, code, raw)
		}
	}
	if code, out, _ := c.do("POST", "/api/automation/runs/clear", "{}"); code != 200 || out["deleted"] != float64(0) {
		t.Fatalf("clear of another user: %d %v", code, out)
	}
	if _, out, raw := c.do("GET", "/api/automation/runs", ""); len(out["runs"].([]any)) != 0 {
		t.Fatalf("another user sees the owner's runs: %s", raw)
	}
	if _, _, raw := c.do("GET", "/api/automation/state", ""); strings.Contains(raw, bookID) {
		t.Fatal("another user sees the owner's runbook")
	}

	c.p = owner
	if _, _, raw := c.do("GET", "/api/automation/state", ""); !strings.Contains(raw, bookID) {
		t.Fatal("the owner's runbook is gone")
	}
	if code, _, raw := c.do("GET", "/api/automation/runs/"+runID+"/export", ""); code != 200 {
		t.Fatalf("the owner's run is gone: %d %s", code, raw)
	}
}

// RS8-H20: another user cannot pause, preview, run or delete the owner's
// schedule; the schedule stays enabled.
func TestOtherUserReachesNoSchedule(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	id := e.approve(t, "0 9 * * *", "UTC")
	mux := http.NewServeMux()
	(&SchedulesHTTP{Schedules: e.s, Secure: func(*http.Request) bool { return true }}).Register(mux)
	do := func(p principal.Principal, method, path string) (int, string) {
		r := httptest.NewRequest(method, "http://webssh.test"+path, strings.NewReader("{}"))
		r = r.WithContext(principal.With(r.Context(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}
	other := principaltest.User(e.p.UserID + 1)
	for _, k := range []struct{ method, path string }{
		{"POST", "/api/automation/schedules/" + id + "/pause"},
		{"POST", "/api/automation/schedules/" + id + "/preview-run"},
		{"DELETE", "/api/automation/schedules/" + id},
	} {
		if code, body := do(other, k.method, k.path); code != http.StatusNotFound {
			t.Errorf("%s %s: %d %s", k.method, k.path, code, body)
		}
	}
	if _, body := do(other, "GET", "/api/automation/schedules"); strings.Contains(body, id) {
		t.Fatal("another user lists the owner's schedule")
	}
	code, body := do(e.p, "GET", "/api/automation/schedules")
	var list struct {
		Schedules []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"schedules"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &list) != nil || len(list.Schedules) != 1 || list.Schedules[0].ID != id || !list.Schedules[0].Enabled {
		t.Fatalf("the owner's schedule changed: %d %s", code, body)
	}
}
