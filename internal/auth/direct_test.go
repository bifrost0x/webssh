package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestSignInDirect(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	a := e.createUser(t, "alice", "password1")
	// MFA on: a passkey sign-in still completes in one step.
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error { return e.flow.Accounts.SetMFARequiredTx(t.Context(), tx, a.ID, true) })
	b := e.browser()
	b.do("POST", "/login", creds("alice", "password1")) // leaves a pending sign-in
	req := func() (*httptest.ResponseRecorder, *http.Request) {
		r := httptest.NewRequest("POST", "/api/webauthn/auth/verify", nil)
		r.AddCookie(&http.Cookie{Name: "session_binding", Value: b.cookies["session_binding"]})
		return httptest.NewRecorder(), r
	}
	w, r := req()
	if err := e.flow.SignInDirect(w, r, a.ID, "passkey", AssurancePhishingResistant); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		b.cookies[c.Name] = c.Value
	}
	p := b.principal(t)
	s, _ := e.flow.Sessions.Lookup(t.Context(), p.SessionID)
	if p.UserID != a.ID || s.Assurance != session.PhishingResistant || strings.Join(s.Methods, ",") != "passkey" ||
		s.PrimaryMethod != "passkey" || s.Remember || s.StrongAt.IsZero() {
		t.Fatalf("%+v", s)
	}
	_, r = req()
	if _, err := e.flow.PendingUser(r); fault.CodeOf(err) != fault.MFARestart {
		t.Fatal("pending sign-in survived the passkey sign-in")
	}
	if !e.audit.has("AUTHENTICATION_SUCCESS") {
		t.Fatalf("audit %v", e.audit.events)
	}
	// Unknown and ineligible accounts get no session.
	w, r = req()
	if err := e.flow.SignInDirect(w, r, a.ID+100, "passkey", AssurancePhishingResistant); fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("unknown account: %v", err)
	}
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE accounts_users SET is_locked = 1 WHERE id = ?`, a.ID)
		return err
	})
	w, r = req()
	if err := e.flow.SignInDirect(w, r, a.ID, "passkey", AssurancePhishingResistant); fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("locked account: %v", err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("cookie set for a refused sign-in")
	}
}
