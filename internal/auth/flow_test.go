package auth

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// fakePasswords keeps passwords in memory; it stands in for
// internal/auth/local, which this package must not import.
type fakePasswords struct {
	mu   sync.Mutex
	pw   map[int64]string
	accs *accounts.Service
}

func (f *fakePasswords) ValidateNew(pw string) string {
	if len([]rune(pw)) < 8 {
		return "Password must be at least 8 characters"
	}
	if len(pw) > 1024 {
		return "Password must not exceed 1024 bytes when encoded as UTF-8"
	}
	return ""
}
func (f *fakePasswords) Hash(_ context.Context, pw string) (string, error) { return "h:" + pw, nil }
func (f *fakePasswords) StoreTx(_ context.Context, _ *store.Tx, id int64, h string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pw[id] = strings.TrimPrefix(h, "h:")
	return nil
}
func (f *fakePasswords) Matches(_ context.Context, id int64, pw string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pw[id] == pw && pw != "", nil
}
func (f *fakePasswords) Name() string { return "password" }
func (f *fakePasswords) Authenticate(ctx context.Context, name, pw string) (int64, error) {
	id, usable, err := f.accs.SignInStanding(ctx, name)
	if err != nil {
		return 0, err
	}
	ok, _ := f.Matches(ctx, id, pw)
	if id == 0 || !usable || !ok {
		return 0, fault.New(fault.AuthFailed, "Invalid username or password")
	}
	return id, nil
}

type fakeFactor struct {
	kind     string
	enrolled map[int64]bool
}

func (f fakeFactor) Kind() string { return f.kind }
func (f fakeFactor) Enrolled(_ context.Context, id int64) (bool, error) {
	return f.enrolled[id], nil
}
func (f fakeFactor) Verify(context.Context, int64, jsontext.Value) error { return nil }

type allGates struct{ off map[string]bool }

func (g allGates) Active(_ context.Context, f string) (bool, error) { return !g.off[f], nil }

type settings struct{ registration bool }

func (s settings) RegistrationEnabled(context.Context) (bool, error) { return s.registration, nil }
func (s settings) LoginLimits(context.Context) (int, int, int, error) {
	return 3, 100, 128, nil
}

type pageCall struct {
	page   string
	status int
	login  LoginView
	form   FormView
}

type fakePages struct {
	mu    sync.Mutex
	calls []pageCall
}

func (p *fakePages) record(w http.ResponseWriter, c pageCall) {
	p.mu.Lock()
	p.calls = append(p.calls, c)
	p.mu.Unlock()
	w.WriteHeader(c.status)
}
func (p *fakePages) Login(w http.ResponseWriter, _ *http.Request, s int, v LoginView) {
	p.record(w, pageCall{page: "login", status: s, login: v})
}
func (p *fakePages) Register(w http.ResponseWriter, _ *http.Request, s int, v FormView) {
	p.record(w, pageCall{page: "register", status: s, form: v})
}
func (p *fakePages) ChangePassword(w http.ResponseWriter, _ *http.Request, s int, v FormView) {
	p.record(w, pageCall{page: "change_password", status: s, form: v})
}
func (p *fakePages) Error(w http.ResponseWriter, _ *http.Request, s int) {
	p.record(w, pageCall{page: "error", status: s})
}
func (p *fakePages) last() pageCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return pageCall{}
	}
	return p.calls[len(p.calls)-1]
}

type audit struct {
	mu     sync.Mutex
	events []string
}

func (a *audit) add(s string)                                { a.mu.Lock(); a.events = append(a.events, s); a.mu.Unlock() }
func (a *audit) Security(e string, kv ...any)                { a.add(e) }
func (a *audit) LoginAttempt(u string, ok bool, _, _ string) { a.add("LOGIN:" + u) }
func (a *audit) Logout(u, _ string)                          { a.add("LOGOUT:" + u) }
func (a *audit) Registration(u string, ok bool, _ string) {
	if ok {
		a.add("REGISTRATION_SUCCESS:" + u)
	} else {
		a.add("REGISTRATION_FAILED:" + u)
	}
}
func (a *audit) PasswordChange(u string, _ bool, _ string) { a.add("PASSWORD_CHANGE:" + u) }
func (a *audit) RateLimitExceeded(e, _, _ string)          { a.add("RATE_LIMIT:" + e) }
func (a *audit) has(prefix string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

type env struct {
	flow  *Flow
	mux   *http.ServeMux
	pages *fakePages
	audit *audit
	pw    *fakePasswords
	totp  fakeFactor
	revs  atomic.Int32
	clock *testClock
}

func newEnv(t *testing.T, reg bool) *env {
	t.Helper()
	db := storetest.Open(t, accounts.Schema(), session.Schema(), Schema())
	ring, err := keyring.Open([]byte("secret"), bytes.Repeat([]byte{1}, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{pages: &fakePages{}, audit: &audit{}, totp: fakeFactor{"totp", map[int64]bool{}}, clock: &testClock{t: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)}}
	e.pw = &fakePasswords{pw: map[int64]string{}}
	accs := &accounts.Service{DB: db, Credentials: e.pw, Audit: e.audit, Now: e.clock.now}
	e.pw.accs = accs
	sess := session.New(db, ring, accs, nil)
	sess.Now = e.clock.now
	sess.Subscribe(func(principal.Revocation) { e.revs.Add(1) })
	lim := NewLimiter()
	lim.Now = e.clock.now
	e.flow = &Flow{
		DB: db, MAC: ring, Accounts: accs, Sessions: sess, Cookie: testCookie{}, Binding: testBinding,
		Password: e.pw, Passwords: e.pw, Factors: []Factor{e.totp}, Gates: allGates{}, Settings: settings{reg},
		Limiter: lim, Limits: Limits{Enabled: true, Login: Rule{5, time.Minute}, Default: Rule{200, time.Hour}},
		Audit: e.audit, Pages: e.pages, Bootstrap: true, Now: e.clock.now,
	}
	e.mux = http.NewServeMux()
	e.flow.Register(e.mux)
	return e
}

type testCookie struct{}

func (testCookie) Set(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Expires: expires, HttpOnly: true})
}
func (testCookie) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "session", MaxAge: -1})
}

// testBinding reads the binding cookie the HTTP edge keeps.
func testBinding(r *http.Request) string {
	if c, err := r.Cookie("session_binding"); err == nil {
		return c.Value
	}
	return ""
}

var bindingSeq atomic.Int64

// browser keeps cookies between requests and puts the principal of a
// valid session into the context, as the HTTP edge does.
type browser struct {
	e       *env
	cookies map[string]string
	ip      string
}

func (e *env) browser() *browser {
	return &browser{e: e, cookies: map[string]string{"session_binding": "binding-" + strconv.FormatInt(bindingSeq.Add(1), 10)}, ip: "192.0.2.1:1234"}
}

func (b *browser) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, body)
	r.RemoteAddr = b.ip
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range b.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	if tok := b.cookies["session"]; tok != "" {
		if p, err := b.e.flow.Sessions.Authenticate(r.Context(), tok); err == nil {
			r = r.WithContext(principal.With(r.Context(), p))
		}
	}
	rec := httptest.NewRecorder()
	b.e.mux.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return rec
}

func (b *browser) principal(t *testing.T) principal.Principal {
	t.Helper()
	p, err := b.e.flow.Sessions.Authenticate(t.Context(), b.cookies["session"])
	if err != nil {
		t.Fatalf("not signed in: %v", err)
	}
	return p
}

func creds(user, pw string) url.Values { return url.Values{"username": {user}, "password": {pw}} }

func (e *env) createUser(t *testing.T, name, pw string) accounts.Account {
	t.Helper()
	a, err := e.flow.Accounts.Create(t.Context(), accounts.CreateRequest{Username: name, Password: pw, ByAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestBootstrapRegistration(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	b := e.browser()
	if rec := b.do("GET", "/login", nil); rec.Code != 302 || rec.Header().Get("Location") != "/register" {
		t.Fatalf("login before bootstrap: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	form := url.Values{"username": {"admin"}, "password": {"password1"}, "confirm_password": {"password2"}}
	b.do("POST", "/register", form)
	if c := e.pages.last(); c.page != "register" || c.form.Flashes[0].Message != "Passwords do not match" {
		t.Fatalf("%+v", c)
	}
	form.Set("confirm_password", "password1")
	rec := b.do("POST", "/register", form)
	if rec.Code != 302 || rec.Header().Get("Location") != "/" {
		t.Fatalf("register %d %s", rec.Code, rec.Header().Get("Location"))
	}
	p := b.principal(t)
	if !p.IsAdmin || p.Username != "admin" {
		t.Fatalf("%+v", p)
	}
	if got := e.flow.TakeFlashes(httptest.NewRequest("GET", "/", nil)); got != nil {
		t.Fatalf("flash leaked to another browser: %v", got)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: b.cookies["session_binding"]})
	if got := e.flow.TakeFlashes(r); len(got) != 1 || got[0].Message != "Account created successfully!" {
		t.Fatalf("flash %v", got)
	}
	// The bootstrap is closed now; registration is off.
	other := e.browser()
	rec = other.do("POST", "/register", url.Values{"username": {"second"}, "password": {"password1"}, "confirm_password": {"password1"}})
	if rec.Code != 302 || rec.Header().Get("Location") != "/login" {
		t.Fatalf("second registration: %d", rec.Code)
	}
	if !e.audit.has("REGISTRATION_SUCCESS:admin") || !e.audit.has("INITIAL_ADMIN_REGISTERED") || !e.audit.has("AUTHENTICATION_SUCCESS") {
		t.Fatalf("audit %v", e.audit.events)
	}
}

// Parallel bootstrap requests create exactly one administrator.
func TestBootstrapRaceHTTP(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	var wg sync.WaitGroup
	var created atomic.Int32
	for i := range 12 {
		wg.Go(func() {
			b := e.browser()
			name := "admin" + string(rune('a'+i))
			rec := b.do("POST", "/register", url.Values{"username": {name}, "password": {"password1"}, "confirm_password": {"password1"}})
			if rec.Code == 302 && rec.Header().Get("Location") == "/" {
				created.Add(1)
			}
		})
	}
	wg.Wait()
	all, _ := e.flow.Accounts.List(t.Context())
	if created.Load() != 1 || len(all) != 1 {
		t.Fatalf("created %d, accounts %d", created.Load(), len(all))
	}
}

func TestLoginSuccessAndFailure(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	e.createUser(t, "alice", "password1")
	locked := e.createUser(t, "locked", "password1")
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE accounts_users SET is_locked = 1 WHERE id = ?`, locked.ID)
		return err
	})
	for _, c := range [][2]string{{"alice", "wrong"}, {"nobody", "password1"}, {"locked", "password1"}, {"ALICE", "password1"}} {
		b := e.browser()
		rec := b.do("POST", "/login", creds(c[0], c[1]))
		got := e.pages.last()
		if rec.Code != 200 || got.page != "login" || got.login.Flashes[0].Message != "Invalid username or password" || got.login.AuthSource != "local" {
			t.Errorf("%v: %d %+v", c, rec.Code, got)
		}
		if b.cookies["session"] != "" {
			t.Errorf("%v: session cookie set", c)
		}
	}
	b := e.browser()
	rec := b.do("POST", "/login?next=/index%3Ftab%3D2", creds("alice", "password1"))
	if rec.Code != 302 || rec.Header().Get("Location") != "/index?tab=2" {
		t.Fatalf("login %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if p := b.principal(t); p.Username != "alice" || !p.IsAdmin {
		t.Fatalf("%+v", p)
	}
	acc, _ := e.flow.Accounts.ByUsername(t.Context(), "alice")
	if acc.LastLogin.IsZero() {
		t.Fatal("last login not recorded")
	}
	// An open redirect target is replaced by the root.
	b2 := e.browser()
	b2.ip = "198.51.100.2:1"
	if rec := b2.do("POST", "/login?next=//evil.example", creds("alice", "password1")); rec.Header().Get("Location") != "/" {
		t.Fatalf("open redirect: %s", rec.Header().Get("Location"))
	}
	// Signed in: the login page redirects home.
	if rec := b.do("GET", "/login", nil); rec.Code != 302 || rec.Header().Get("Location") != "/" {
		t.Fatalf("signed-in login page %d", rec.Code)
	}
}

func TestRememberMeLifetime(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	e.createUser(t, "alice", "password1")
	b := e.browser()
	form := creds("alice", "password1")
	form.Set("remember", "on")
	b.do("POST", "/login", form)
	p := b.principal(t)
	s, _ := e.flow.Sessions.Lookup(t.Context(), p.SessionID)
	if !s.Remember || s.ExpiresAt.Sub(s.AuthenticatedAt) != session.RememberLifetime {
		t.Fatalf("%+v", s)
	}
}

func TestLoginRateLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	e.createUser(t, "alice", "password1")
	b := e.browser()
	// The per-name limit (3 per minute here) counts failures only.
	for range 2 {
		b.do("POST", "/login", creds("alice", "wrong"))
	}
	b2 := e.browser()
	b2.do("POST", "/login", creds("alice", "password1"))
	b2.principal(t) // success released its reservation
	b.do("POST", "/login", creds("alice", "wrong"))
	b.do("POST", "/login", creds("alice", "password1"))
	if got := e.pages.last(); got.login.Flashes[0].Message != msgTooManyLogins {
		t.Fatalf("name limit not applied: %+v", got)
	}
	if b.cookies["session"] != "" {
		t.Fatal("signed in despite the limit")
	}
	// Another source keeps its own budget for the same name.
	c := e.browser()
	c.ip = "198.51.100.7:1"
	c.do("POST", "/login", creds("alice", "password1"))
	c.principal(t)
	// The per-source limit (5 per minute) counts every attempt.
	d := e.browser()
	d.ip = "203.0.113.9:1"
	for i := range 5 {
		d.do("POST", "/login", creds("nobody"+string(rune('a'+i)), "x"))
	}
	d.do("POST", "/login", creds("alice", "password1"))
	if d.cookies["session"] != "" || !e.audit.has("RATE_LIMIT:login") {
		t.Fatal("source limit not applied")
	}
	e.clock.add(time.Minute)
	d.do("POST", "/login", creds("alice", "password1"))
	d.principal(t)
}

func TestPendingSecondFactor(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	a := e.createUser(t, "alice", "password1")
	e.totp.enrolled[a.ID] = true
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error { return e.flow.Accounts.SetMFARequiredTx(t.Context(), tx, a.ID, true) })
	b := e.browser()
	rec := b.do("POST", "/login?next=/x", creds("alice", "password1"))
	got := e.pages.last()
	if rec.Code != 200 || !got.login.MFARequired || len(got.login.MFAMethods) != 1 || got.login.MFAMethods[0] != "totp" {
		t.Fatalf("%d %+v", rec.Code, got)
	}
	if b.cookies["session"] != "" {
		t.Fatal("signed in before the factor")
	}
	req := func(br *browser) (*httptest.ResponseRecorder, *http.Request) {
		r := httptest.NewRequest("POST", "/api/totp/auth/verify", nil)
		for k, v := range br.cookies {
			r.AddCookie(&http.Cookie{Name: k, Value: v})
		}
		return httptest.NewRecorder(), r
	}
	// Another browser cannot finish it.
	w, r := req(e.browser())
	if _, err := e.flow.PendingUser(r); fault.CodeOf(err) != fault.MFARestart {
		t.Fatalf("foreign browser: %v", err)
	}
	if _, err := e.flow.CompletePending(w, r, a.ID, "totp", session.MFA); fault.CodeOf(err) != fault.MFARestart {
		t.Fatal("foreign browser completed the sign-in")
	}
	w, r = req(b)
	if id, err := e.flow.PendingUser(r); err != nil || id != a.ID {
		t.Fatalf("pending user %d %v", id, err)
	}
	if _, err := e.flow.CompletePending(w, r, a.ID+1, "totp", session.MFA); err == nil {
		t.Fatal("completed for another user")
	}
	// The failed attempt above consumed the pending sign-in.
	b.do("POST", "/login?next=/x", creds("alice", "password1"))
	w, r = req(b)
	next, err := e.flow.CompletePending(w, r, a.ID, "totp", session.MFA)
	if err != nil || next != "/x" {
		t.Fatalf("complete %q %v", next, err)
	}
	for _, c := range w.Result().Cookies() {
		b.cookies[c.Name] = c.Value
	}
	p := b.principal(t)
	s, _ := e.flow.Sessions.Lookup(t.Context(), p.SessionID)
	if s.Assurance != session.MFA || strings.Join(s.Methods, ",") != "password,totp" || s.StrongAt.IsZero() {
		t.Fatalf("%+v", s)
	}
	// Used once.
	w, r = req(b)
	if _, err := e.flow.CompletePending(w, r, a.ID, "totp", session.MFA); fault.CodeOf(err) != fault.MFARestart {
		t.Fatal("pending sign-in reused")
	}
}

func TestPendingExpiresAndCancel(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	a := e.createUser(t, "alice", "password1")
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error { return e.flow.Accounts.SetMFARequiredTx(t.Context(), tx, a.ID, true) })
	b := e.browser()
	b.do("POST", "/login", creds("alice", "password1"))
	r := httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: b.cookies["session_binding"]})
	e.clock.add(PendingTTL)
	if _, err := e.flow.PendingUser(r); fault.CodeOf(err) != fault.MFARestart {
		t.Fatal("pending sign-in outlived its TTL")
	}
	e.clock.add(-PendingTTL)
	b.do("POST", "/login", creds("alice", "password1"))
	if rec := b.do("POST", "/login/cancel", url.Values{}); rec.Header().Get("Location") != "/login" {
		t.Fatalf("cancel %d", rec.Code)
	}
	r = httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: b.cookies["session_binding"]})
	if _, err := e.flow.PendingUser(r); err == nil {
		t.Fatal("pending sign-in survived cancel")
	}
	// A password change between the password and the factor voids it.
	b.do("POST", "/login", creds("alice", "password1"))
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := e.flow.Accounts.PasswordChangedTx(t.Context(), tx, a.ID, "h")
		return err
	})
	w := httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: b.cookies["session_binding"]})
	if _, err := e.flow.CompletePending(w, r, a.ID, "totp", session.MFA); fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("stale generation completed: %v", err)
	}
}

func TestDiscardPendingFlashes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	a := e.createUser(t, "alice", "password1")
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error { return e.flow.Accounts.SetMFARequiredTx(t.Context(), tx, a.ID, true) })
	b := e.browser()
	b.do("POST", "/login", creds("alice", "password1"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: b.cookies["session_binding"]})
	_ = w
	e.flow.DiscardPending(r, Flash{"error", "Too many invalid codes. Sign in again."})
	b.do("GET", "/login", nil)
	if got := e.pages.last(); len(got.login.Flashes) != 1 || got.login.Flashes[0].Message != "Too many invalid codes. Sign in again." {
		t.Fatalf("%+v", got)
	}
	if _, err := e.flow.PendingUser(r); err == nil {
		t.Fatal("pending kept")
	}
}

func TestLogoutRevokesOnlyThisSession(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	e.createUser(t, "alice", "password1")
	b, other := e.browser(), e.browser()
	b.do("POST", "/login", creds("alice", "password1"))
	other.do("POST", "/login", creds("alice", "password1"))
	tok := b.cookies["session"]
	rec := b.do("POST", "/logout", url.Values{})
	if rec.Code != 302 || rec.Header().Get("Location") != "/login" || b.cookies["session"] != "" {
		t.Fatalf("logout %d %v", rec.Code, b.cookies)
	}
	if _, err := e.flow.Sessions.Authenticate(t.Context(), tok); err == nil {
		t.Fatal("copied cookie still valid after logout")
	}
	other.principal(t)
	if e.revs.Load() != 1 || !e.audit.has("LOGOUT:alice") {
		t.Fatalf("revocations %d", e.revs.Load())
	}
	// Signed out: logout redirects to the sign-in.
	if rec := e.browser().do("POST", "/logout", url.Values{}); rec.Header().Get("Location") != "/login" {
		t.Fatal("anonymous logout")
	}
}

func TestChangePassword(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	e.createUser(t, "alice", "password1")
	b, other := e.browser(), e.browser()
	b.do("POST", "/login", creds("alice", "password1"))
	other.do("POST", "/login", creds("alice", "password1"))
	old := b.principal(t)
	cases := []struct{ cur, next, confirm, want string }{
		{"wrong", "newpassword", "newpassword", "Current password is incorrect"},
		{"password1", "newpassword", "different", "New passwords do not match"},
		{"password1", "short", "short", "New password must be at least 8 characters"},
		{"password1", strings.Repeat("a", 1025), strings.Repeat("a", 1025), "New password must not exceed 1024 bytes when encoded as UTF-8"},
		{"password1", "password1", "password1", "New password must be different from current password"},
	}
	for _, c := range cases {
		b.do("POST", "/change-password", url.Values{"current_password": {c.cur}, "new_password": {c.next}, "confirm_password": {c.confirm}})
		if got := e.pages.last(); got.page != "change_password" || got.form.Flashes[0].Message != c.want {
			t.Errorf("%s: %+v", c.want, got)
		}
	}
	b.do("POST", "/change-password", url.Values{"current_password": {"password1"}, "new_password": {"newpassword"}, "confirm_password": {"newpassword"}})
	if got := e.pages.last(); got.form.Flashes[0].Message != "Too many attempts. Please try again later." {
		t.Fatalf("change-password limit: %+v", got)
	}
	e.clock.add(time.Minute)
	rec := b.do("POST", "/change-password", url.Values{"current_password": {"password1"}, "new_password": {"newpassword"}, "confirm_password": {"newpassword"}})
	if rec.Code != 302 || rec.Header().Get("Location") != "/" {
		t.Fatalf("change %d", rec.Code)
	}
	fresh := b.principal(t)
	if fresh.SessionID == old.SessionID {
		t.Fatal("session not rotated")
	}
	if _, err := e.flow.Sessions.Authenticate(t.Context(), other.cookies["session"]); err == nil {
		t.Fatal("other browser still signed in")
	}
	if e.revs.Load() != 2 {
		t.Fatalf("revocations %d", e.revs.Load())
	}
	oldS, _ := e.flow.Sessions.Lookup(t.Context(), fresh.SessionID)
	if oldS.AuthGeneration != 1 {
		t.Fatalf("generation %d", oldS.AuthGeneration)
	}
	if ok, _ := e.pw.Matches(t.Context(), fresh.UserID, "newpassword"); !ok {
		t.Fatal("password not stored")
	}
	if !e.audit.has("PASSWORD_CHANGE:alice") {
		t.Fatal("not audited")
	}
}

func TestChangePasswordRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	e.createUser(t, "first", "password1")
	a := e.createUser(t, "dir", "password1")
	b := e.browser()
	b.do("POST", "/login", creds("dir", "password1"))
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE accounts_users SET managed_by = 'ldap' WHERE id = ?`, a.ID)
		return err
	})
	b.do("GET", "/change-password", nil)
	if got := e.pages.last(); got.page != "error" || got.status != 403 {
		t.Fatalf("managed account: %+v", got)
	}
	if rec := e.browser().do("GET", "/change-password", nil); rec.Header().Get("Location") != "/login" {
		t.Fatal("anonymous change-password")
	}
}

func TestOngoingRegistration(t *testing.T) {
	t.Parallel()
	e := newEnv(t, true)
	e.createUser(t, "first", "password1")
	e.flow.Accounts.Admins = accounts.Admins{"reserved"}
	b := e.browser()
	b.do("GET", "/register", nil)
	if e.pages.last().page != "register" {
		t.Fatal("registration page not shown")
	}
	b.do("POST", "/register", url.Values{"username": {"Reserved"}, "password": {"password1"}, "confirm_password": {"password1"}})
	if got := e.pages.last(); got.form.Flashes[0].Message != "Username already exists" || !e.audit.has("REGISTRATION_FAILED:Reserved") {
		t.Fatalf("%+v", got)
	}
	rec := b.do("POST", "/register", url.Values{"username": {"second"}, "password": {"password1"}, "confirm_password": {"password1"}})
	if rec.Code != 302 || b.principal(t).IsAdmin {
		t.Fatal("ongoing registration")
	}
}
