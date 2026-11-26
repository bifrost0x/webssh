package auth

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestFlightsTakeOnceAndBindToBrowser(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	s := &Flights{Now: func() time.Time { return now }}
	f := NewFlight(ProviderOIDC, PurposeSignIn, now)
	if err := s.Put("", f); err == nil {
		t.Fatal("flight without browser binding stored")
	}
	if err := s.Put("browser-a", f); err != nil {
		t.Fatal(err)
	}
	// Another browser's callback with the same state finds nothing and
	// does not consume the flight.
	if _, err := s.Take("browser-b", f.State); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("foreign browser: %v", err)
	}
	got, err := s.Take("browser-a", f.State)
	if err != nil || got.Nonce != f.Nonce || got.Verifier != f.Verifier {
		t.Fatalf("take: %+v %v", got, err)
	}
	if _, err := s.Take("browser-a", f.State); !fault.Is(err, fault.AuthFailed) {
		t.Fatal("flight taken twice")
	}
	old := NewFlight(ProviderOIDC, PurposeSignIn, now.Add(-FlightTTL))
	_ = s.Put("browser-a", old)
	if _, err := s.Take("browser-a", old.State); !fault.Is(err, fault.AuthFailed) {
		t.Fatal("expired flight accepted")
	}
	dropped := NewFlight(ProviderOIDC, PurposeSignIn, now)
	_ = s.Put("browser-a", dropped)
	s.Drop("browser-a", dropped.State)
	if _, err := s.Take("browser-a", dropped.State); err == nil {
		t.Fatal("dropped flight taken")
	}
}

func TestFlightsBounds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	s := &Flights{Now: func() time.Time { return now }}
	var states []string
	for range MaxFlightsPerBinding + 3 {
		f := NewFlight(ProviderOIDC, PurposeSignIn, now)
		states = append(states, f.State)
		if err := s.Put("browser", f); err != nil {
			t.Fatal(err)
		}
	}
	for i, st := range states {
		_, err := s.Take("browser", st)
		if kept := i >= 3; kept != (err == nil) {
			t.Fatalf("flight %d: kept=%v err=%v", i, kept, err)
		}
	}
	for i := range maxFlights + 10 {
		_ = s.Put("b"+strings.Repeat("x", i%50)+string(rune('a'+i%26))+itoa(int64(i)), NewFlight(ProviderOIDC, PurposeSignIn, now))
	}
	s.mu.Lock()
	n := len(s.m)
	s.mu.Unlock()
	if n > maxFlights {
		t.Fatalf("%d flights kept", n)
	}
}

func FuzzFlightsTake(f *testing.F) {
	f.Add("browser", "state")
	f.Fuzz(func(t *testing.T, binding, state string) {
		now := time.Now()
		s := &Flights{Now: func() time.Time { return now }}
		fl := NewFlight(ProviderOIDC, PurposeSignIn, now)
		_ = s.Put("browser", fl)
		if _, err := s.Take(binding, state); err == nil && (binding != "browser" || state != fl.State) {
			t.Fatal("flight taken with other values")
		}
	})
}

func externalRequest(b *browser) (*httptest.ResponseRecorder, *http.Request) {
	r := httptest.NewRequest("GET", "/oidc/callback", nil)
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: b.cookies["session_binding"]})
	return httptest.NewRecorder(), r
}

func TestSignInExternal(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	a := e.createUser(t, "alice", "password1")
	b := e.browser()
	b.do("GET", "/login", nil)
	authTime := e.clock.now().Add(-time.Minute)

	// Without MFA the provider sign-in opens the session at once.
	w, r := externalRequest(b)
	if err := e.flow.SignInExternal(w, r, ExternalSignIn{UserID: a.ID, Method: "oidc", Assurance: AssuranceBasic, Continuation: "/settings"}); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/settings" {
		t.Fatalf("answer %d %s", w.Code, w.Header().Get("Location"))
	}
	sess := sessionOf(t, e, w)
	if sess.PrimaryMethod != "oidc" || sess.Assurance != session.Basic || !sess.StrongAt.IsZero() || sess.Remember {
		t.Fatalf("session %+v", sess)
	}

	// A strong provider sign-in keeps the provider's auth_time, not now,
	// so the recent step-up window starts there.
	w, r = externalRequest(b)
	if err := e.flow.SignInExternal(w, r, ExternalSignIn{UserID: a.ID, Method: "oidc", Assurance: AssuranceMFA, StrongAt: authTime}); err != nil {
		t.Fatal(err)
	}
	if sess = sessionOf(t, e, w); sess.Assurance != session.MFA || !sess.StrongAt.Equal(authTime) {
		t.Fatalf("strong session %+v", sess)
	}

	// MFA required and a BASIC provider answer: a local factor follows,
	// recovery codes are not offered.
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error { return e.flow.Accounts.SetMFARequiredTx(t.Context(), tx, a.ID, true) })
	w, r = externalRequest(b)
	if err := e.flow.SignInExternal(w, r, ExternalSignIn{UserID: a.ID, Method: "oidc", Assurance: AssuranceBasic}); !fault.Is(err, fault.Forbidden) {
		t.Fatalf("no local factor: %v", err)
	}
	e.totp.enrolled[a.ID] = true
	w, r = externalRequest(b)
	if err := e.flow.SignInExternal(w, r, ExternalSignIn{UserID: a.ID, Method: "oidc", Assurance: AssuranceBasic}); err != nil {
		t.Fatal(err)
	}
	page := e.pages.last()
	if !page.login.MFARequired || page.login.AuthSource != "oidc" || !slices.Equal(page.login.MFAMethods, []string{"totp"}) {
		t.Fatalf("page %+v", page)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("a session cookie before the second factor")
	}
	_, r = externalRequest(b)
	if id, err := e.flow.PendingUser(r); err != nil || id != a.ID {
		t.Fatalf("pending %d %v", id, err)
	}
	// With an MFA answer of the provider the local factor is skipped.
	w, r = externalRequest(b)
	if err := e.flow.SignInExternal(w, r, ExternalSignIn{UserID: a.ID, Method: "oidc", Assurance: AssuranceMFA, StrongAt: authTime}); err != nil || w.Code != http.StatusFound {
		t.Fatalf("strong sign-in with MFA required: %d %v", w.Code, err)
	}

	// Locked and unknown accounts get no session.
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE accounts_users SET is_locked = 1 WHERE id = ?`, a.ID)
		return err
	})
	w, r = externalRequest(b)
	if err := e.flow.SignInExternal(w, r, ExternalSignIn{UserID: a.ID, Method: "oidc", Assurance: AssuranceMFA}); err == nil || len(w.Result().Cookies()) != 0 {
		t.Fatalf("locked account signed in: %v", err)
	}
	w, r = externalRequest(b)
	if err := e.flow.SignInExternal(w, r, ExternalSignIn{UserID: a.ID + 99, Method: "oidc"}); !fault.Is(err, fault.AuthenticationNeeded) {
		t.Fatalf("unknown account: %v", err)
	}
}

func sessionOf(t *testing.T, e *env, w *httptest.ResponseRecorder) session.Session {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			s, err := e.flow.Sessions.Validate(t.Context(), c.Value)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	t.Fatal("no session cookie")
	return session.Session{}
}
