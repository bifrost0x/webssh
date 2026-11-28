package settings

import (
	"context"
	json "encoding/json/v2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

type fakeGates map[string]bool

func (g fakeGates) FeatureActive(_ context.Context, feature string) (bool, error) {
	return g[feature], nil
}

func newHTTP(t *testing.T) (*HTTP, *http.ServeMux) {
	t.Helper()
	s, _ := newService(t, Environment{})
	h := &HTTP{Settings: s, Gates: fakeGates{"totp": true}, BasePath: "/ws",
		Tour: TourDeployment{Values: map[string]bool{"TOTP_ENABLED": true, "SESSION_COOKIE_SECURE": true, "SMB_ENABLED": true}, AdminPanelEnabled: true}}
	mux := http.NewServeMux()
	h.Register(mux)
	return h, mux
}

type reply struct {
	status int
	body   map[string]any
	raw    string
}

func call(t *testing.T, mux *http.ServeMux, p *principal.Principal, method, path, body, contentType string) reply {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if p != nil {
		r = r.WithContext(principal.With(r.Context(), *p))
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	out := reply{status: w.Code, raw: w.Body.String()}
	if err := json.Unmarshal(w.Body.Bytes(), &out.body); err != nil {
		t.Fatalf("%s %s: %v: %s", method, path, err, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%s %s: Cache-Control %q", method, path, w.Header().Get("Cache-Control"))
	}
	return out
}

func TestPreferences(t *testing.T) {
	_, mux := newHTTP(t)
	u := principaltest.User(3)
	r := call(t, mux, &u, "POST", "/api/account/preferences", `{"theme":"noir","authentication_session_duration_minutes":60}`, "application/json")
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	settings := r.body["settings"].(map[string]any)
	if settings["theme"] != "noir" || settings["authentication_session_duration_minutes"] != float64(60) {
		t.Errorf("%s", r.raw)
	}
	if _, ok := settings["notepad"]; ok {
		t.Error("the notepad is not a setting")
	}
	cases := []struct{ body, ctype, msg, code string }{
		{`{}`, "application/json", msgNothingToChange, "invalid_request"},
		{`{"notepad":"x"}`, "application/json", msgNothingToChange, "invalid_request"},
		{`[]`, "application/json", msgNothingToChange, "invalid_request"},
		{`{"theme":"noir"}`, "text/plain", msgNothingToChange, "invalid_request"},
		{`{"theme":"nope"}`, "application/json", msgInvalidTheme, "invalid_value"},
		{`{"theme":1}`, "application/json", msgInvalidTheme, "invalid_value"},
		{`{"confirm_session_close":"true"}`, "application/json", msgInvalidConfirm, "invalid_value"},
		{`{"sync_terminal_directory":1}`, "application/json", msgInvalidSync, "invalid_value"},
		{`{"authentication_session_duration_minutes":60.0}`, "application/json", msgInvalidDuration, "invalid_value"},
		{`{"terminal_appearance":{"font_size":4}}`, "application/json", msgInvalidAppearance, "invalid_value"},
		{`{"disconnect_session_action":"x"}`, "application/json", msgInvalidDisconnect, "invalid_value"},
		// The first invalid member in the order of the Python route.
		{`{"theme":"nope","start_page":"files"}`, "application/json", msgInvalidStartPage, "invalid_value"},
	}
	for _, c := range cases {
		r := call(t, mux, &u, "POST", "/api/account/preferences", c.body, c.ctype)
		if r.status != 400 || r.body["error"] != c.msg || r.body["code"] != c.code || r.body["success"] != false {
			t.Errorf("%s: %d %s", c.body, r.status, r.raw)
		}
	}
	big := `{"theme":"` + strings.Repeat("x", maxBody) + `"}`
	if r := call(t, mux, &u, "POST", "/api/account/preferences", big, "application/json"); r.status != 413 {
		t.Errorf("oversized body: %d", r.status)
	}
	// For duplicate names the last one wins, as in json.loads.
	if r := call(t, mux, &u, "POST", "/api/account/preferences", `{"theme":"nope","theme":"paper"}`, "application/json"); r.status != 200 || r.body["settings"].(map[string]any)["theme"] != "paper" {
		t.Errorf("duplicate member: %d %s", r.status, r.raw)
	}
	if r := call(t, mux, &u, "POST", "/api/account/preferences", `{"theme":"glass"}`, "application/vnd.webssh+json"); r.status != 200 {
		t.Errorf("+json media type: %d", r.status)
	}
}

func TestRoutesRequireAnAccount(t *testing.T) {
	_, mux := newHTTP(t)
	recovery := principaltest.User(3)
	recovery.Recovery = true
	for _, rt := range [][2]string{{"POST", "/api/account/preferences"}, {"GET", "/api/account/tour"},
		{"POST", "/api/account/tour"}, {"PUT", "/api/overview/preferences"},
		{"GET", "/api/account/notices"}, {"POST", "/api/account/notices/acknowledge"}} {
		if r := call(t, mux, nil, rt[0], rt[1], `{"theme":"noir"}`, "application/json"); r.status != 401 {
			t.Errorf("%v without principal: %d", rt, r.status)
		}
		if r := call(t, mux, &recovery, rt[0], rt[1], `{"theme":"noir"}`, "application/json"); r.status != 403 {
			t.Errorf("%v in a recovery session: %d", rt, r.status)
		}
	}
}

func TestOverviewPreferences(t *testing.T) {
	_, mux := newHTTP(t)
	u := principaltest.User(2)
	r := call(t, mux, &u, "PUT", "/api/overview/preferences", `{"panels":[{"id":"hosts","w":4,"h":30,"hidden":false}],"dismissed":["reboot:a"]}`, "application/json")
	if r.status != 200 || !strings.Contains(r.raw, `"panels":[{"id":"hosts","w":4,"h":30,"hidden":false}]`) || !strings.Contains(r.raw, `"dismissed":["reboot:a"]`) {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	if r := call(t, mux, &u, "PUT", "/api/overview/preferences", `{"panels":null}`, "application/json"); r.raw != `{"dismissed":["reboot:a"],"panels":null}` {
		t.Errorf("reset: %s", r.raw)
	}
	// The codes of the Python release.
	for body, want := range map[string][2]string{
		`{}`:                            {"Invalid request.", "invalid_request"},
		`{"other":1}`:                   {"Invalid request.", "invalid_request"},
		`{"panels":[{"id":"x","w":4}]}`: {msgInvalidPanels, "invalid_layout"},
		`{"dismissed":["x"]}`:           {msgInvalidDismissed, "invalid_dismissed"},
		`{"panels":5,"dismissed":5}`:    {msgInvalidPanels, "invalid_layout"},
	} {
		if r := call(t, mux, &u, "PUT", "/api/overview/preferences", body, "application/json"); r.status != 400 || r.body["error"] != want[0] || r.body["code"] != want[1] {
			t.Errorf("%s: %d %s", body, r.status, r.raw)
		}
	}
}

func TestOverviewPreferencesStorageFailure(t *testing.T) {
	h, mux := newHTTP(t)
	h.Logger = slog.New(slog.DiscardHandler)
	err := h.Settings.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DROP TABLE settings_user`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	u := principaltest.User(2)
	r := call(t, mux, &u, "PUT", "/api/overview/preferences", `{"panels":null}`, "application/json")
	if r.status != 500 || r.body["code"] != "storage" || r.body["error"] != msgOverviewNotSaved {
		t.Errorf("%d %s", r.status, r.raw)
	}
}

func TestTour(t *testing.T) {
	_, mux := newHTTP(t)
	u := principaltest.User(5)
	if r := call(t, mux, &u, "POST", "/api/account/tour", `{"state":"completed"}`, "application/json"); r.status != 400 || r.body["error"] != msgAcknowledgeMissing {
		t.Errorf("completed without acknowledgement: %s", r.raw)
	}
	for _, body := range []string{`{"state":"later"}`, `{"state":"new","x":1}`, `{"acknowledged":true}`, `{"state":1}`} {
		if r := call(t, mux, &u, "POST", "/api/account/tour", body, "application/json"); r.status != 400 || r.body["error"] != msgInvalidTourState {
			t.Errorf("%s: %s", body, r.raw)
		}
	}
	if r := call(t, mux, &u, "POST", "/api/account/tour", `{"state":"dismissed","acknowledged":"anything"}`, "application/json"); r.raw != `{"state":"dismissed"}` {
		t.Errorf("dismiss: %s", r.raw)
	}
	r := call(t, mux, &u, "GET", "/api/account/tour", "", "")
	if r.body["state"] != "dismissed" || r.body["administrator"] != false || r.body["admin_url"] != nil || r.body["process_root"] != nil {
		t.Errorf("user view: %s", r.raw)
	}
	for _, f := range r.body["facts"].([]any) {
		fact := f.(map[string]any)
		if len(fact) != 2 || fact["key"] == "SESSION_COOKIE_SECURE" || fact["key"] == "BOOTSTRAP_REGISTRATION_ENABLED" {
			t.Errorf("user sees deployment posture: %v", fact)
		}
	}
	if r := call(t, mux, &u, "POST", "/api/account/tour", `{"state":"completed","acknowledged":true}`, "application/json"); r.status != 200 {
		t.Fatal(r.raw)
	}
	a := principaltest.Admin(1)
	r = call(t, mux, &a, "GET", "/api/account/tour", "", "")
	if r.body["state"] != "new" || r.body["admin_url"] != "/ws/admin" {
		t.Errorf("admin view: %s", r.raw)
	}
	facts := map[string]map[string]any{}
	for _, f := range r.body["facts"].([]any) {
		fact := f.(map[string]any)
		facts[fact["key"].(string)] = fact
	}
	if len(facts) != 14 {
		t.Errorf("%d facts", len(facts))
	}
	if f := facts["TOTP_ENABLED"]; f["enabled"] != true || f["configured"] != true || f["source"] != "deployment_and_admin" {
		t.Errorf("gated fact %v", f)
	}
	if f := facts["WEBAUTHN_ENABLED"]; f["enabled"] != false || f["configured"] != false {
		t.Errorf("gated fact %v", f)
	}
	if f := facts["TMUX_ENABLED"]; f["source"] != "default" {
		t.Errorf("runtime fact %v", f)
	}
	if f := facts["SESSION_COOKIE_SECURE"]; f["enabled"] != true || f["source"] != "environment" {
		t.Errorf("environment fact %v", f)
	}
	if f := facts["registration_enabled"]; f["source"] != "admin" {
		t.Errorf("admin fact %v", f)
	}
}
