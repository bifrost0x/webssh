package httpapi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
)

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEdge(t)
	for _, target := range []string{"/health", "/api/credentials/state", "/missing", "/static/css/style.css"} {
		w := e.do(req{target: target})
		h := w.Header()
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "connect-src 'self';") || strings.Contains(csp, "ws:") {
			t.Errorf("%s: CSP %q", target, csp)
		}
		for name, want := range map[string]string{
			"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "X-XSS-Protection": "0",
			"Referrer-Policy": "strict-origin-when-cross-origin", "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		} {
			if got := h.Get(name); got != want {
				t.Errorf("%s: %s = %q, want %q", target, name, got, want)
			}
		}
		if target != "/static/css/style.css" && h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", target, h.Get("Cache-Control"))
		}
	}
}

func TestNoHSTSInDebug(t *testing.T) {
	e := newEdge(t, withConfig(func(c *config.Config) { c.Debug = true }))
	if got := e.do(req{target: "/health"}).Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS %q in debug mode", got)
	}
}

// A preview route answers 501 before the session lookup and without
// reading the body, also without a CSRF token.
func TestPreviewRouteLetsNothingThrough(t *testing.T) {
	e := newEdge(t)
	body := &countingReader{r: strings.NewReader(`{"name":"x"}`)}
	r := httptest.NewRequest(http.MethodPost, "http://webssh.test/api/credentials/apply", body)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "session", Value: "tok-alice"})
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status %d", w.Code)
	}
	if want := `{"success":false,"code":"not_available_in_preview","error":"Not available in this preview yet."}`; strings.TrimSpace(w.Body.String()) != want {
		t.Fatalf("body %s", w.Body)
	}
	if e.sessions.calls.Load() != 0 || body.n != 0 {
		t.Fatalf("session lookups %d, body bytes read %d; want none", e.sessions.calls.Load(), body.n)
	}
	// A page route of the preview answers in plain text.
	w = e.do(req{target: "/automation"})
	if w.Code != http.StatusNotImplemented || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("/automation: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestSocketIOIsGone(t *testing.T) {
	e := newEdge(t)
	for _, target := range []string{"/socket.io/?EIO=4&transport=polling", "/socket.io"} {
		w := e.do(req{target: target})
		if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), `"realtime":"webssh.v1"`) {
			t.Errorf("%s: %d %s", target, w.Code, w.Body)
		}
	}
}

func TestAdminPanelDisabledHidesAdministration(t *testing.T) {
	e := newEdge(t, withConfig(func(c *config.Config) { c.Accounts.AdminPanelEnabled = false }))
	e.h.Mux().HandleFunc("GET /admin/api/users", echo)
	for _, target := range []string{"/admin", "/admin/api/users", "/admin/api/audit"} {
		if w := e.do(req{target: target, token: "tok-root"}); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", target, w.Code)
		}
	}
	if w := e.do(req{method: http.MethodPost, target: "/api/step-up/password", token: "tok-root"}); w.Code != http.StatusNotFound {
		t.Errorf("admin step-up: status %d, want 404", w.Code)
	}
}

func TestAccessLevels(t *testing.T) {
	e := newEdge(t)
	mux := e.h.Mux()
	mux.HandleFunc("GET /api/account/sessions", echo)
	mux.HandleFunc("GET /api/account/security-state", echo)
	mux.HandleFunc("GET /admin/api/users", echo)
	mux.HandleFunc("GET /login", echo)
	mux.HandleFunc("GET /{$}", echo)
	cases := []struct {
		name, target, token string
		want                int
	}{
		{"public without session", "/login", "", 200},
		{"public with session keeps the principal", "/login", "tok-alice", 200},
		{"user API without session", "/api/account/sessions", "", 401},
		{"user API with unknown token", "/api/account/sessions", "revoked", 401},
		{"user API", "/api/account/sessions", "tok-alice", 200},
		{"user API refuses recovery", "/api/account/sessions", "tok-repair", 403},
		{"repair API admits recovery", "/api/account/security-state", "tok-repair", 200},
		{"admin API for a user", "/admin/api/users", "tok-alice", 403},
		{"admin API for recovery", "/admin/api/users", "tok-repair", 403},
		{"admin API", "/admin/api/users", "tok-root", 200},
		{"page without session", "/", "", 302},
	}
	for _, c := range cases {
		w := e.do(req{target: c.target, token: c.token})
		if w.Code != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, w.Code, c.want, w.Body)
		}
	}
	if w := e.do(req{target: "/login", token: "tok-alice"}); w.Header().Get("X-User") != "1" {
		t.Error("the principal of a public route is missing")
	}
}

// A recovery session that reaches another API gets the Python code
// recovery_required.
func TestRecoverySessionGetsRecoveryRequired(t *testing.T) {
	e := newEdge(t)
	w := e.do(req{target: "/api/account/sessions", token: "tok-repair"})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"code":"recovery_required"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// Fix: an API request without a valid session gets 401 JSON, not the
// sign-in page (account-controls.spec.js:29 expects 302 from Python).
func TestRevokedSessionGets401AndLosesCookie(t *testing.T) {
	e := newEdge(t)
	w := e.do(req{target: "/api/account/sessions", token: "revoked"})
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"code":"authentication_required"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the stale session cookie is not removed")
	}
}

func TestPageRedirectsToSignInWithNext(t *testing.T) {
	e := newEdge(t, withConfig(func(c *config.Config) {
		c.Proxies.Hops = 1
		c.ApplicationRoot = "/webssh"
	}))
	w := e.do(req{target: "/settings?tab=security", remote: "127.0.0.1:4000", headers: map[string]string{
		"X-Forwarded-For": "192.0.2.7", "X-Forwarded-Prefix": "/webssh",
	}})
	if w.Code != http.StatusFound {
		t.Fatalf("status %d", w.Code)
	}
	if got, want := w.Header().Get("Location"), "/webssh/login?next=%2Fwebssh%2Fsettings%3Ftab%3Dsecurity"; got != want {
		t.Fatalf("Location %q, want %q", got, want)
	}
}

func TestSessionLookupFailureFailsClosed(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /login", echo)
	e.sessions.err = errors.New("database is locked")
	w := e.do(req{target: "/login", token: "tok-alice", headers: map[string]string{"Accept": "application/json"}})
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "locked") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestUpgradeRouteSkipsSessionAndLimits(t *testing.T) {
	e := newEdge(t)
	reached := false
	e.h.Mux().HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if s, h := Origin(r); s != "http" || h != "webssh.test" {
			t.Errorf("Origin = %q %q", s, h)
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	e.do(req{target: "/ws", token: "tok-alice"})
	if !reached || e.sessions.calls.Load() != 0 {
		t.Fatalf("reached %v, session lookups %d", reached, e.sessions.calls.Load())
	}
}

func TestPanicBecomes500(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /login", func(http.ResponseWriter, *http.Request) { panic("boom") })
	if w := e.do(req{target: "/login"}); w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(e.logs.String(), "handler panicked") {
		t.Fatal("panic not logged")
	}
}

func TestRequestLogHasNoSecrets(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /login", echo)
	e.do(req{target: "/login?code=secret-code", token: "tok-alice", headers: map[string]string{"Authorization": "Bearer secret-bearer"}})
	logs := e.logs.String()
	for _, secret := range []string{"secret-code", "tok-alice", "secret-bearer"} {
		if strings.Contains(logs, secret) {
			t.Errorf("log contains %q:\n%s", secret, logs)
		}
	}
	if !strings.Contains(logs, "path=/login") || !strings.Contains(logs, "user_id=1") {
		t.Errorf("request line missing:\n%s", logs)
	}
}

func TestRealtimeStatus(t *testing.T) {
	e := newEdge(t)
	w := e.do(req{target: "/api/realtime/status"})
	if w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), `"code":"authentication_required"`) ||
		!strings.Contains(w.Body.String(), `"schema":1`) {
		t.Fatalf("anonymous: %d %s", w.Code, w.Body)
	}
	w = e.do(req{target: "/api/realtime/status", token: "tok-alice"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"authenticated":true`) ||
		!strings.Contains(w.Body.String(), `"subprotocols":["webssh.v1"]`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("signed in: %d %s", w.Code, w.Body)
	}
	w = e.do(req{target: "/api/realtime/status", token: "tok-repair"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"recovery":true`) {
		t.Fatalf("recovery: %d %s", w.Code, w.Body)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without dependencies succeeded")
	}
	cfg := testConfig()
	cfg.Cookies.RememberName = "session_binding"
	if _, err := New(Options{Config: cfg, Sessions: &fakeSessions{}, MAC: fakeMAC{}, Assets: testAssets(t)}); err == nil {
		t.Fatal("a remember cookie named like the binding cookie was accepted")
	}
}

func TestConfigureServer(t *testing.T) {
	srv := &http.Server{ReadTimeout: 1, WriteTimeout: 1}
	ConfigureServer(srv)
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || srv.ReadHeaderTimeout == 0 || srv.IdleTimeout == 0 || srv.MaxHeaderBytes == 0 {
		t.Fatalf("%+v", srv)
	}
}

func TestWriteFaultHidesCause(t *testing.T) {
	e := newEdge(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	writeFault(w, r, e.h.log, errors.New("/data/app.db: disk I/O error"))
	if w.Code != 500 || strings.Contains(w.Body.String(), "disk") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	writeFault(w, r, e.h.log, &fault.Error{Code: fault.RateLimited, RetryAfter: 1500_000_000})
	if w.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
}

// A directory check of another request answers every request of the
// account with 503 ldap_validation_in_progress and Retry-After, pages
// included, as the Python before-request check did.
func TestSessionLookupWhileTheDirectoryChecks(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /settings", echo)
	inProgress := fault.New(fault.LDAPValidationInProgress, "Directory session validation is in progress")
	inProgress.RetryAfter = time.Second
	e.sessions.err = inProgress
	w := e.do(req{target: "/settings", token: "tok-alice"})
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" ||
		!strings.Contains(w.Body.String(), `"code":"ldap_validation_in_progress"`) {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
	if strings.Contains(w.Header().Get("Set-Cookie"), "session=;") {
		t.Fatal("the session cookie must stay: the check only runs elsewhere")
	}
}
