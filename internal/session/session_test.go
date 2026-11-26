package session

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type fakeAccounts struct {
	mu sync.Mutex
	m  map[int64]Standing
}

func (f *fakeAccounts) Standing(_ context.Context, id int64) (Standing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[id], nil
}

func (f *fakeAccounts) set(id int64, fn func(*Standing)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.m[id]
	fn(&s)
	f.m[id] = s
}

type minutes int

func (m minutes) SessionMinutes(context.Context, int64) (int, error) { return int(m), nil }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testRing(t testing.TB) *keyring.Ring {
	t.Helper()
	r, err := keyring.Open([]byte("test-secret"), bytes.Repeat([]byte{7}, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type fixture struct {
	svc      *Service
	accounts *fakeAccounts
	clock    *clock
	revs     []principal.Revocation
	mu       sync.Mutex
}

func newFixture(t *testing.T, d Durations) *fixture {
	t.Helper()
	f := &fixture{
		accounts: &fakeAccounts{m: map[int64]Standing{
			1: {Exists: true, Username: "alice", IsAdmin: true},
			2: {Exists: true, Username: "bob"},
		}},
		clock: &clock{t: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)},
	}
	f.svc = New(storetest.Open(t, Schema()), testRing(t), f.accounts, d)
	f.svc.Now = f.clock.now
	f.svc.Subscribe(func(r principal.Revocation) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.revs = append(f.revs, r)
	})
	return f
}

func (f *fixture) revocations() []principal.Revocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]principal.Revocation(nil), f.revs...)
}

func (f *fixture) issue(t *testing.T, user int64, remember bool) (Session, string) {
	t.Helper()
	st, _ := f.accounts.Standing(t.Context(), user)
	s, tok, err := f.svc.Issue(t.Context(), IssueRequest{UserID: user, Generation: st.Generation, PrimaryMethod: "password", Methods: []string{"password"}, Assurance: Basic, Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	return s, tok
}

func wantAuthNeeded(t *testing.T, err error, what string) {
	t.Helper()
	if fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("%s: %v", what, err)
	}
}

func TestIssueAndAuthenticate(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	s, tok := f.issue(t, 1, false)
	p, err := f.svc.Authenticate(t.Context(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != 1 || p.SessionID != s.ID || !p.IsAdmin || p.Username != "alice" || p.Recovery {
		t.Fatalf("principal %+v", p)
	}
	if got := s.ExpiresAt.Sub(s.AuthenticatedAt); got != 30*time.Minute {
		t.Fatalf("default lifetime %v", got)
	}
	// Only the MAC is stored.
	var dump string
	err = f.svc.db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT id || hex(token_mac) || methods FROM session_sessions`).Scan(&dump)
	})
	if err != nil || strings.Contains(dump, tok) {
		t.Fatalf("token stored or unreadable: %v", err)
	}
	for _, bad := range []string{"", tok + "x", strings.Repeat("a", 200), strings.ToUpper(tok)} {
		_, err := f.svc.Authenticate(t.Context(), bad)
		wantAuthNeeded(t, err, "bad token")
	}
}

func TestLifetimes(t *testing.T) {
	t.Parallel()
	for m, want := range map[minutes]time.Duration{480: 8 * time.Hour, 60: time.Hour, 45: 30 * time.Minute, 0: 30 * time.Minute} {
		f := newFixture(t, m)
		s, _ := f.issue(t, 2, false)
		if got := s.ExpiresAt.Sub(s.AuthenticatedAt); got != want {
			t.Errorf("setting %d: %v, want %v", m, got, want)
		}
		r, _ := f.issue(t, 2, true)
		if got := r.ExpiresAt.Sub(r.AuthenticatedAt); got != RememberLifetime {
			t.Errorf("remember: %v", got)
		}
	}
}

// An expired session is refused, removed and its end published.
func TestExpiry(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	s, tok := f.issue(t, 2, false)
	f.clock.add(30 * time.Minute)
	_, err := f.svc.Authenticate(t.Context(), tok)
	wantAuthNeeded(t, err, "expired")
	revs := f.revocations()
	if len(revs) != 1 || revs[0].SessionID != s.ID || revs[0].Reason != principal.ReasonExpired {
		t.Fatalf("revocations %+v", revs)
	}
	_, tok2 := f.issue(t, 2, false)
	f.clock.add(31 * time.Minute)
	if n, err := f.svc.Sweep(t.Context()); err != nil || n != 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	_, err = f.svc.Authenticate(t.Context(), tok2)
	wantAuthNeeded(t, err, "swept")
}

// A raised generation (password change, lock) and a lock end every
// session at once; Check sees it, even for a principal held by a
// realtime connection.
func TestGenerationLockAndRights(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	_, tok := f.issue(t, 1, false)
	p, _ := f.svc.Authenticate(t.Context(), tok)
	if err := f.svc.Check(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	f.accounts.set(1, func(s *Standing) { s.IsAdmin = false })
	wantAuthNeeded(t, f.svc.Check(t.Context(), p), "admin rights removed")
	f.accounts.set(1, func(s *Standing) { s.IsAdmin = true; s.Locked = true })
	wantAuthNeeded(t, f.svc.Check(t.Context(), p), "locked")
	_, err := f.svc.Authenticate(t.Context(), tok)
	wantAuthNeeded(t, err, "locked token")
	f.accounts.set(1, func(s *Standing) { s.Locked = false; s.Generation = 1 })
	wantAuthNeeded(t, f.svc.Check(t.Context(), p), "generation")
	// Issuing against a stale generation is refused.
	_, _, err = f.svc.Issue(t.Context(), IssueRequest{UserID: 1, Generation: 0, PrimaryMethod: "password", Methods: []string{"password"}, Assurance: Basic})
	wantAuthNeeded(t, err, "stale issue")
	// A directory-managed administrator is never eligible.
	f.accounts.set(1, func(s *Standing) { s.Managed = true })
	_, _, err = f.svc.Issue(t.Context(), IssueRequest{UserID: 1, Generation: 1, PrimaryMethod: "password", Methods: []string{"password"}, Assurance: Basic})
	wantAuthNeeded(t, err, "managed admin")
	// Unknown account.
	_, _, err = f.svc.Issue(t.Context(), IssueRequest{UserID: 9, PrimaryMethod: "password", Methods: []string{"password"}, Assurance: Basic})
	wantAuthNeeded(t, err, "unknown")
	// A principal for another user's session is refused.
	_, tok2 := f.issue(t, 2, false)
	p2, _ := f.svc.Authenticate(t.Context(), tok2)
	forged := p2
	forged.UserID = 1
	wantAuthNeeded(t, f.svc.Check(t.Context(), forged), "forged principal")
}

func TestIssueValidatesMethods(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	for _, req := range []IssueRequest{
		{UserID: 2, PrimaryMethod: "password", Methods: nil, Assurance: Basic},
		{UserID: 2, PrimaryMethod: "password", Methods: []string{"totp"}, Assurance: Basic},
		{UserID: 2, PrimaryMethod: "password", Methods: []string{"password", "Bad"}, Assurance: Basic},
		{UserID: 2, PrimaryMethod: "password", Methods: []string{"password"}, Assurance: "SUPER"},
		{UserID: 2, PrimaryMethod: "password", Methods: []string{"password", "a", "b", "c", "d", "e", "f", "g", "h"}, Assurance: Basic},
	} {
		if _, _, err := f.svc.Issue(t.Context(), req); err == nil {
			t.Errorf("accepted %+v", req)
		}
	}
	s, _, err := f.svc.Issue(t.Context(), IssueRequest{UserID: 2, PrimaryMethod: "password", Methods: []string{"password", "totp", "totp"}, Assurance: MFA})
	if err != nil || len(s.Methods) != 2 || s.StrongAt.IsZero() {
		t.Fatalf("%+v %v", s, err)
	}
}

// Revocations are published once per session, after the commit and
// before the call returns (condition K6).
func TestRevocationPublishing(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	a, _ := f.issue(t, 2, false)
	b, tokB := f.issue(t, 2, false)
	c, _ := f.issue(t, 2, false)
	other, otherTok := f.issue(t, 1, false)
	seenCommitted := false
	cancel := f.svc.Subscribe(func(r principal.Revocation) {
		if r.SessionID == a.ID {
			// The row is already gone when the revocation arrives.
			_, err := f.svc.Lookup(context.Background(), a.ID)
			seenCommitted = fault.CodeOf(err) == fault.AuthenticationNeeded
		}
	})
	defer cancel()
	if err := f.svc.Revoke(t.Context(), a.ID, principal.ReasonLogout); err != nil {
		t.Fatal(err)
	}
	if !seenCommitted {
		t.Fatal("revocation published before the commit")
	}
	n, err := f.svc.RevokeUser(t.Context(), 2, principal.ReasonPasswordChanged, b.ID)
	if err != nil || n != 1 {
		t.Fatalf("RevokeUser %d %v", n, err)
	}
	if _, err := f.svc.Authenticate(t.Context(), tokB); err != nil {
		t.Fatal("excepted session ended")
	}
	revs := f.revocations()
	want := []principal.Revocation{{a.ID, 2, principal.ReasonLogout}, {c.ID, 2, principal.ReasonPasswordChanged}}
	if len(revs) != 2 || revs[0] != want[0] || revs[1] != want[1] {
		t.Fatalf("revocations %+v", revs)
	}
	// Revoke-all raises the epoch: every session ends, also ones issued
	// before by a copy of the old state.
	if n, err := f.svc.RevokeAll(t.Context(), principal.ReasonAccountLocked); err != nil || n != 2 {
		t.Fatalf("RevokeAll %d %v", n, err)
	}
	_, err = f.svc.Authenticate(t.Context(), otherTok)
	wantAuthNeeded(t, err, "after revoke-all")
	_ = other
	_, tok := f.issue(t, 1, false)
	if _, err := f.svc.Authenticate(t.Context(), tok); err != nil {
		t.Fatalf("new session after revoke-all: %v", err)
	}
}

func TestRecoverySessions(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	s, tok, err := f.svc.Issue(t.Context(), IssueRequest{UserID: 2, PrimaryMethod: "password", Methods: []string{"password", MethodRecovery}, Assurance: MFA})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := f.svc.Authenticate(t.Context(), tok)
	if !p.Recovery {
		t.Fatal("recovery flag missing")
	}
	// A principal that hides the restriction is refused.
	hidden := p
	hidden.Recovery = false
	wantAuthNeeded(t, f.svc.Check(t.Context(), hidden), "hidden recovery")
	if _, err := principal.Require(principal.With(t.Context(), p)); fault.CodeOf(err) != fault.Forbidden {
		t.Fatal("recovery principal passes Require")
	}
	ok, err := f.svc.ClearRecovery(t.Context(), s.ID, "totp", false)
	if err != nil || !ok {
		t.Fatalf("clear %v %v", ok, err)
	}
	p, _ = f.svc.Authenticate(t.Context(), tok)
	got, _ := f.svc.Lookup(t.Context(), s.ID)
	if p.Recovery || strings.Join(got.Methods, ",") != "password,totp" {
		t.Fatalf("after clear: %+v %v", p, got.Methods)
	}
	if ok, _ := f.svc.ClearRecovery(t.Context(), s.ID, "", true); ok {
		t.Fatal("cleared twice")
	}
	if _, err := f.svc.ClearRecovery(t.Context(), "missing", "", false); fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("missing: %v", err)
	}
}

func withPrincipal(r *http.Request, p principal.Principal) *http.Request {
	return r.WithContext(principal.With(r.Context(), p))
}

func TestSessionListAndRevokeHTTP(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	cur, curTok := f.issue(t, 2, false)
	f.clock.add(time.Minute)
	old, oldTok := f.issue(t, 2, true)
	f.issue(t, 1, false)
	p, _ := f.svc.Authenticate(t.Context(), curTok)
	var audit []string
	h := &HTTP{Service: f.svc, Audit: auditFunc(func(e string, kv ...any) { audit = append(audit, e) })}
	mux := http.NewServeMux()
	h.Register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, withPrincipal(httptest.NewRequest("GET", "/api/account/sessions", nil), p))
	var list struct {
		Sessions []sessionJSON `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(list.Sessions) != 2 || list.Sessions[0].Current || !list.Sessions[1].Current {
		t.Fatalf("list %+v", list.Sessions)
	}
	if !strings.HasSuffix(list.Sessions[1].StartedAt, "Z") || list.Sessions[1].StartedAt != "2026-11-26T10:00:00Z" {
		t.Fatalf("started_at %q", list.Sessions[1].StartedAt)
	}
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, withPrincipal(httptest.NewRequest("POST", "/api/account/sessions/revoke", strings.NewReader(body)), p))
		return rec
	}
	for body, code := range map[string]int{
		`{}`: 400, `{"others": false}`: 400, `{"others": true, "x": 1}`: 400, `{"session": "abc"}`: 400,
		`{"others": true, "others": true}`: 400, `[]`: 400,
		`{"session": "` + strings.Repeat("0", 64) + `"}`:   404,
		`{"session": "` + Handle(f.svc.mac, cur.ID) + `"}`: 409,
	} {
		if rec := post(body); rec.Code != code {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
	rec = post(`{"session": "` + Handle(f.svc.mac, old.ID) + `"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"revoked":1`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if _, err := f.svc.Authenticate(t.Context(), oldTok); err == nil {
		t.Fatal("revoked session still valid")
	}
	if len(audit) != 1 || audit[0] != "BROWSER_LOGINS_REVOKED" {
		t.Fatalf("audit %v", audit)
	}
	// Without a principal: 401.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/account/sessions", nil))
	if rec.Code != 401 {
		t.Fatalf("anonymous %d", rec.Code)
	}
	rec = post(`{"others": true}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"revoked":0`) {
		t.Fatalf("others %d %s", rec.Code, rec.Body)
	}
}

type auditFunc func(event string, kv ...any)

func (f auditFunc) Security(event string, kv ...any) { f(event, kv...) }

func TestCookies(t *testing.T) {
	t.Parallel()
	c := Cookies{Name: "session", Path: "/webssh", Secure: true}
	rec := httptest.NewRecorder()
	c.Set(rec, "tok", Session{Remember: true, ExpiresAt: time.Now().Add(time.Hour)})
	ck := rec.Result().Cookies()[0]
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/webssh" || ck.MaxAge <= 0 {
		t.Fatalf("cookie %+v", ck)
	}
	rec = httptest.NewRecorder()
	c.Set(rec, "tok", Session{})
	if ck := rec.Result().Cookies()[0]; ck.MaxAge != 0 || !ck.Expires.IsZero() {
		t.Fatalf("browser-session cookie got an expiry: %+v", ck)
	}
	req := httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	b := c.Binding(rec, req)
	if !validBinding(b) {
		t.Fatalf("binding %q", b)
	}
	req.AddCookie(&http.Cookie{Name: "session" + BindingSuffix, Value: b})
	if c.Binding(httptest.NewRecorder(), req) != b || c.CurrentBinding(req) != b {
		t.Fatal("binding not reused")
	}
	bad := httptest.NewRequest("GET", "/", nil)
	bad.AddCookie(&http.Cookie{Name: "session" + BindingSuffix, Value: "short"})
	if c.CurrentBinding(bad) != "" {
		t.Fatal("malformed binding accepted")
	}
}

func TestPyISO(t *testing.T) {
	t.Parallel()
	if got := pyISO(time.Date(2026, 1, 2, 3, 4, 5, 250000000, time.UTC)); got != "2026-01-02T03:04:05.250000" {
		t.Fatal(got)
	}
}
