package auth

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// TestSignInDirectRefusedAfterConcurrentFactorReset: an administrator's
// MFA reset that deletes the passkey and raises the generation after the
// assertion was verified must not leave the passkey's sign-in a session.
func TestSignInDirectRefusedAfterConcurrentFactorReset(t *testing.T) {
	t.Parallel()
	e := newEnv(t, false)
	a := e.createUser(t, "alice", "password1")
	reset := func() {
		err := e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
			_, err := e.flow.Accounts.InvalidateTx(t.Context(), tx, a.ID, principal.ReasonFactorChanged)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// The assertion was verified, then the reset committed: the passkey
	// is gone when the sign-in confirms it.
	reset()
	gone := func(context.Context) error { return fault.New(fault.AuthenticationNeeded, "") }
	w, r := httptest.NewRecorder(), httptest.NewRequest("POST", "/api/webauthn/auth/verify", nil)
	if err := e.flow.SignInDirect(w, r, a.ID, "passkey", AssurancePhishingResistant, gone); fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("reset before the check: %v", err)
	}
	// The reset commits after the check: the session refuses the old
	// generation.
	late := func(context.Context) error { reset(); return nil }
	w, r = httptest.NewRecorder(), httptest.NewRequest("POST", "/api/webauthn/auth/verify", nil)
	if err := e.flow.SignInDirect(w, r, a.ID, "passkey", AssurancePhishingResistant, late); fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("reset after the check: %v", err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			if _, err := e.flow.Sessions.Authenticate(t.Context(), c.Value); err == nil {
				t.Fatal("passkey sign-in holds a session after the factor reset")
			}
		}
	}
}
