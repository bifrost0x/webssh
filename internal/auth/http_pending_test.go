package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestFlowSignInAdaptsThePendingSignIn(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	a := e.createUser(t, "alice", "password1")
	e.totp.enrolled[a.ID] = true
	_ = e.flow.DB.Write(t.Context(), func(tx *store.Tx) error { return e.flow.Accounts.SetMFARequiredTx(t.Context(), tx, a.ID, true) })
	b := e.browser()
	b.do("POST", "/login", creds("alice", "password1"))
	req := func(br *browser) (*httptest.ResponseRecorder, *http.Request) {
		r := httptest.NewRequest("POST", "/api/totp/auth/verify", nil)
		for k, v := range br.cookies {
			r.AddCookie(&http.Cookie{Name: k, Value: v})
		}
		return httptest.NewRecorder(), r
	}
	signIn := e.flow.SignIn()

	_, r := req(e.browser())
	if _, err := signIn.Pending(r); fault.CodeOf(err) != fault.MFARestart {
		t.Fatalf("foreign browser: %v", err)
	}
	_, r = req(b)
	p, err := signIn.Pending(r)
	if err != nil || p.UserID != a.ID || p.PrimaryMethod != "password" {
		t.Fatalf("pending %+v %v", p, err)
	}

	// Discard ends it and leaves the restart notice with the name hint.
	w, r := req(b)
	if err := signIn.Discard(w, r); err != nil {
		t.Fatal(err)
	}
	if _, err := signIn.Pending(r); fault.CodeOf(err) != fault.MFARestart {
		t.Fatalf("pending after discard: %v", err)
	}
	flashes := e.flow.TakeFlashes(r)
	want := []Flash{{"error", restartMessage}, {"login_auth_source", "local"}, {"login_username", "alice"}}
	if len(flashes) != len(want) {
		t.Fatalf("flashes %+v", flashes)
	}
	for i := range want {
		if flashes[i] != want[i] {
			t.Fatalf("flashes %+v", flashes)
		}
	}

	// Complete issues the session with the factor's assurance.
	b.do("POST", "/login", creds("alice", "password1"))
	w, r = req(b)
	next, err := signIn.Complete(w, r, a.ID, "totp", AssuranceMFA)
	if err != nil || next != "/" {
		t.Fatalf("complete %q %v", next, err)
	}
}
