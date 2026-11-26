package webauthn

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type fakeAccounts struct {
	mu  sync.Mutex
	mfa map[int64]bool
}

func (a *fakeAccounts) MFARequired(_ context.Context, _ *store.Tx, id int64) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.mfa[id], nil
}

func (a *fakeAccounts) SetMFARequired(_ context.Context, _ *store.Tx, id int64, on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mfa[id] = on
	return nil
}

type fakeGates struct {
	mu  sync.Mutex
	off map[string]bool
}

func (g *fakeGates) Active(_ context.Context, f string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.off[f], nil
}

func (g *fakeGates) set(f string, on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.off[f] = !on
}

type fakeSessions struct {
	mu    sync.Mutex
	ended []string
}

func (s *fakeSessions) EndRecovery(_ context.Context, _ *store.Tx, id, replacement string, basic bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = append(s.ended, id+"|"+replacement+"|"+strconv.FormatBool(basic))
	return nil
}

type fakeTOTP struct{ n int }

func (f fakeTOTP) Count(context.Context, *store.Tx, int64) (int, error) { return f.n, nil }
func (fakeTOTP) RemoveAll(context.Context, *store.Tx, int64) error      { return nil }

// grantStepUp accepts the grant "ok" for the expected action and target.
type grantStepUp struct {
	mu       sync.Mutex
	consumed []string
}

func (g *grantStepUp) Consume(_ context.Context, _ principal.Principal, action principal.Action, target, grant string) error {
	if grant != "ok" {
		return fault.New(fault.StepUpRequired, "")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.consumed = append(g.consumed, string(action)+":"+target)
	return nil
}

// fakePending is the pending sign-in of each browser binding.
type fakePending struct {
	mu        sync.Mutex
	users     map[string]int64
	completed []string
}

func (f *fakePending) Pending(r *http.Request) (auth.PendingLogin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.users[testBrowser(r)]
	if !ok {
		return auth.PendingLogin{}, fault.New(fault.AuthenticationNeeded, "")
	}
	return auth.PendingLogin{UserID: id, PrimaryMethod: "password"}, nil
}

func (f *fakePending) Complete(_ http.ResponseWriter, r *http.Request, userID int64, factor string, a auth.Assurance) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.users[testBrowser(r)] != userID {
		return "", fault.New(fault.MFARestart, "")
	}
	delete(f.users, testBrowser(r))
	f.completed = append(f.completed, strconv.FormatInt(userID, 10)+"|"+factor+"|"+string(a))
	return "/next", nil
}

func (f *fakePending) Discard(http.ResponseWriter, *http.Request) error { return nil }

type fakeDirect struct {
	mu      sync.Mutex
	signins []string
	refuse  map[int64]bool
}

func (f *fakeDirect) SignInDirect(_ http.ResponseWriter, _ *http.Request, userID int64, method string, a auth.Assurance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse[userID] {
		return fault.New(fault.AuthenticationNeeded, "")
	}
	f.signins = append(f.signins, strconv.FormatInt(userID, 10)+"|"+method+"|"+string(a))
	return nil
}

type recordedAudit struct {
	mu     sync.Mutex
	events []string
}

func (a *recordedAudit) Security(_ context.Context, _ slog.Level, event string, _ ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
}

func (a *recordedAudit) has(event string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Contains(a.events, event)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	svc      *Service
	http     *HTTP
	mux      *http.ServeMux
	accounts *fakeAccounts
	gates    *fakeGates
	sessions *fakeSessions
	stepUp   *grantStepUp
	pending  *fakePending
	direct   *fakeDirect
	audit    *recordedAudit
	clock    *clock
	limiter  *auth.Limiter
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.Open(t, auth.Schema(), Schema())
	ring, err := keyring.Open([]byte("test-secret"), bytes.Repeat([]byte{3}, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{accounts: &fakeAccounts{mfa: map[int64]bool{}}, gates: &fakeGates{off: map[string]bool{}}, sessions: &fakeSessions{},
		stepUp: &grantStepUp{}, pending: &fakePending{users: map[string]int64{}}, direct: &fakeDirect{refuse: map[int64]bool{}},
		audit: &recordedAudit{}, clock: &clock{t: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}}
	e.svc = &Service{DB: db, Ring: ring, RP: testRP, Now: e.clock.Now, Recovery: &auth.Recovery{DB: db}}
	e.svc.MFA = &auth.MFA{DB: db, Accounts: e.accounts, Gates: e.gates, TOTP: fakeTOTP{}, Passkeys: e.svc, Sessions: e.sessions}
	e.limiter = auth.NewLimiter()
	e.limiter.Now = e.clock.Now
	e.http = &HTTP{Service: e.svc, Gates: e.gates, StepUp: e.stepUp, Pending: e.pending, SignIn: e.direct, Binding: testBrowser,
		Limits: auth.FactorLimits{Limiter: e.limiter, Enabled: true, Login: auth.Rule{Limit: 10, Window: time.Minute},
			ClientAddr: func(r *http.Request) string { return r.RemoteAddr }},
		Audit: e.audit}
	e.mux = http.NewServeMux()
	e.http.Register(e.mux)
	return e
}

// testBrowser is the browser binding: the X-Test-Browser header.
func testBrowser(r *http.Request) string { return r.Header.Get("X-Test-Browser") }

func user(id int64) principal.Principal {
	return principal.Principal{UserID: id, Username: "user" + strconv.FormatInt(id, 10), SessionID: "session-of-user-" + strconv.FormatInt(id, 10)}
}

type call struct {
	method, path string
	body         any
	p            *principal.Principal
	browser      string
	grant        string
	addr         string
}

func (e *env) do(t *testing.T, c call) (int, map[string]jsontext.Value) {
	t.Helper()
	var body []byte
	if c.body != nil {
		var err error
		if body, err = json.Marshal(c.body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(c.method, c.path, bytes.NewReader(body))
	if c.p != nil {
		r = r.WithContext(principal.With(r.Context(), *c.p))
	}
	r.Header.Set("X-Test-Browser", c.browser)
	if c.grant != "" {
		r.Header.Set(auth.StepUpHeader, c.grant)
	}
	r.RemoteAddr = "192.0.2.1"
	if c.addr != "" {
		r.RemoteAddr = c.addr
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	var out map[string]jsontext.Value
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: %d %q", c.method, c.path, w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %s: cacheable response", c.method, c.path)
	}
	return w.Code, out
}

func str(t *testing.T, v jsontext.Value) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		t.Fatalf("%s is not a string", v)
	}
	return s
}

// enrol registers a passkey of alg for p through the HTTP routes and
// returns its authenticator and row id.
func (e *env) enrol(t *testing.T, p principal.Principal, alg int64, name string) (*authenticator, int64) {
	t.Helper()
	code, opts := e.do(t, call{method: "POST", path: "/api/webauthn/register/options", body: map[string]any{}, p: &p, grant: "ok"})
	if code != 200 {
		t.Fatalf("options: %d %v", code, opts)
	}
	ch, err := decodeB64URL(str(t, opts["challenge"]))
	if err != nil {
		t.Fatal(err)
	}
	a := newAuthenticator(t, testRP, alg, UserHandle(p.UserID))
	code, out := e.do(t, call{method: "POST", path: "/api/webauthn/register/verify", p: &p,
		body: map[string]any{"ceremony": str(t, opts["ceremony"]), "name": name, "credential": a.register(t, ch, attNone)}})
	if code != 201 {
		t.Fatalf("verify: %d %v", code, out)
	}
	id, err := strconv.ParseInt(string(out["id"]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return a, id
}

// signInOptions requests sign-in options for browser and returns the
// challenge and the allowed credential IDs.
func (e *env) signInOptions(t *testing.T, browser string) ([]byte, []string) {
	t.Helper()
	code, opts := e.do(t, call{method: "POST", path: "/api/webauthn/auth/options", body: map[string]any{}, browser: browser})
	if code != 200 {
		t.Fatalf("auth options: %d %v", code, opts)
	}
	ch, err := decodeB64URL(str(t, opts["challenge"]))
	if err != nil {
		t.Fatal(err)
	}
	var allow []descriptorJSON
	if err := json.Unmarshal(opts["allowCredentials"], &allow); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(allow))
	for _, d := range allow {
		ids = append(ids, d.ID)
	}
	return ch, ids
}

func browserID(n int) string { return "browser-binding-" + strings.Repeat("x", 8) + strconv.Itoa(n) }

// The service is the passkey factor of the auth registry and the passkey
// counter of auth.MFA; stepup.Passkeys is asserted by the composition root.
var (
	_ auth.Factor        = Factor{}
	_ auth.DurableFactor = (*Service)(nil)
	_ DirectSignIn       = (*auth.Flow)(nil)
)
