package operations

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

func pythonBin(t *testing.T) string {
	t.Helper()
	for _, p := range []string{os.Getenv("WEBSSH_PYTHON"), "../../.venv/bin/python"} {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	t.Skip("no Python virtual environment")
	return ""
}

// pythonSupport calls create_support_report of app/support_report.py with
// the facts of each case patched in, and prints status and body.
const pythonSupport = `
import json, sys, flask
from app import support_report as s
import app.health as health
spec = json.load(sys.stdin)
out = []
web = flask.Flask("t")
for c in spec:
    f = c["features"]
    s.current_user = type("U", (), {"is_admin": c["admin"], "is_authenticated": True})()
    s.runtime_feature_status = lambda name, f=f: {"enabled": f.get("tmux", False)}
    s.is_automation_enabled = lambda f=f: f.get("automation", False)
    s.is_credentials_enabled = lambda f=f: f.get("saved_passwords", False)
    s.feature_is_active = lambda name, f=f: f.get(name, False)
    s.config.SMB_ENABLED = f.get("smb", False)
    s.config.DEPLOYMENT_PROFILE = c["profile"]
    s.config.BLOCK_INTERNAL_SSH = c["blocked"]
    web.config["SESSION_COOKIE_SECURE"] = c["secure_cookie"]
    failed = c["failed"]
    health.ready = lambda failed=failed: (flask.jsonify({"status": "not_ready", "failed": failed}), 503) if failed else flask.jsonify({"status": "ready"})
    base = "https://h" if c["https"] else "http://h"
    with web.test_request_context("/api/account/support-report", method="POST", data=c["body"], content_type="application/json", base_url=base):
        r = s.create_support_report.__wrapped__()
        resp, status = (r if isinstance(r, tuple) else (r, 200))
        body = resp.get_json()
        if isinstance(body, dict):
            body.pop("generated_at", None)
            body.pop("version", None)
        out.append({"status": status, "body": body})
sys.stdout.write("\n--result--\n" + json.dumps(out))
`

type supportCase struct {
	Body         string          `json:"body"`
	Admin        bool            `json:"admin"`
	HTTPS        bool            `json:"https"`
	Features     map[string]bool `json:"features"`
	Failed       []string        `json:"failed"`
	Profile      string          `json:"profile"`
	Blocked      bool            `json:"blocked"`
	SecureCookie bool            `json:"secure_cookie"`
}

type caseFacts struct{ c supportCase }

func (f caseFacts) Version() string { return "test" }
func (f caseFacts) ReadinessFailures(context.Context) []string {
	return f.c.Failed
}
func (f caseFacts) Features(context.Context) map[string]bool { return f.c.Features }
func (f caseFacts) Deployment() SupportDeployment {
	return SupportDeployment{Profile: f.c.Profile, SecureCookie: f.c.SecureCookie, InternalSSHBlocked: f.c.Blocked}
}

var supportCases = []supportCase{
	{Body: `{}`, Profile: "homelab", Features: map[string]bool{}},
	{Body: `{"area":"files","reference":"SMB-ABCDEF123456"}`, Admin: true, HTTPS: true, Profile: "production",
		Blocked: true, SecureCookie: true, Features: map[string]bool{"smb": true, "tmux": true, "passkey": true, "ldap": true}},
	{Body: `{"area":"sign_in"}`, Admin: true, Profile: "staging", Failed: []string{"database", "other", "maintenance"},
		Features: map[string]bool{"automation": true, "saved_passwords": true, "totp": true, "oidc": true, "recovery": true}},
	{Body: `{"area":"ssh","reference":""}`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: `{"area":"nope"}`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: `{"area":"files","reference":"SMB-abcdef123456"}`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: `{"area":"files","reference":"SMB-ABCDEF1234567"}`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: `{"area":"files","extra":1}`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: `{"area":5}`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: `{"reference":null}`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: `[]`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: `"general"`, Features: map[string]bool{}, Profile: "homelab"},
	{Body: ``, Features: map[string]bool{}, Profile: "homelab"},
}

// The report has the shape, members, filters and refusals of the Python
// release for the same facts.
func TestSupportReportMatchesPython(t *testing.T) {
	python := pythonBin(t)
	in, _ := json.Marshal(supportCases)
	cmd := exec.CommandContext(t.Context(), python, "-c", pythonSupport)
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "DATA_DIR="+t.TempDir(), "SECRET_KEY=differential-test-only-0123456789abcdef", "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = bytes.NewReader(in)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python: %v\n%s", err, raw)
	}
	_, result, ok := strings.Cut(string(raw), "\n--result--\n")
	if !ok {
		t.Fatalf("python output: %s", raw)
	}
	var want []struct {
		Status int            `json:"status"`
		Body   map[string]any `json:"body"`
	}
	if err := json.Unmarshal([]byte(result), &want); err != nil {
		t.Fatal(err)
	}
	for i, c := range supportCases {
		h := &SupportHTTP{Facts: caseFacts{c}, HTTPS: func(*http.Request) bool { return c.HTTPS },
			Now: func() time.Time { return time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC) }}
		mux := http.NewServeMux()
		h.Register(mux)
		p := principaltest.User(5)
		p.IsAdmin = c.Admin
		r := httptest.NewRequest(http.MethodPost, "/api/account/support-report", strings.NewReader(c.Body))
		r = r.WithContext(principal.With(r.Context(), p))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if g, ok := got["generated_at"].(string); w.Code == 200 && (!ok || g != "2026-11-27T09:00:00+00:00") {
			t.Errorf("case %d: generated_at %v", i, got["generated_at"])
		}
		delete(got, "generated_at")
		delete(got, "version")
		gb, _ := json.Marshal(got, json.Deterministic(true))
		wb, _ := json.Marshal(want[i].Body, json.Deterministic(true))
		if w.Code != want[i].Status || string(gb) != string(wb) {
			t.Errorf("case %d %s:\n got %d %s\nwant %d %s", i, c.Body, w.Code, gb, want[i].Status, wb)
		}
		if w.Code == 200 && !isSortedObject(w.Body.Bytes()) {
			t.Errorf("case %d: members not in the sorted order of jsonify: %s", i, w.Body.Bytes())
		}
	}
}

// isSortedObject reports whether the top-level members come in sorted
// order, as Flask's jsonify sends them.
func isSortedObject(b []byte) bool {
	var keys []string
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	rest := string(b)
	for k := range m {
		keys = append(keys, k)
	}
	last := -1
	for _, k := range sortedStrings(keys) {
		i := strings.Index(rest, `"`+k+`":`)
		if i < last {
			return false
		}
		last = i
	}
	return true
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
