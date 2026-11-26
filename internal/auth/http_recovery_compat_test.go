package auth

import (
	"testing"
)

func TestStandaloneRecoveryIsRefused(t *testing.T) {
	t.Parallel()
	e := newFactorEnv(t)
	e.h.RegisterRecoveryCompat(e.mux)
	e.accounts.mfa[4] = true
	code, out := e.do(t, nil, "POST", "/login/recovery", `{"username": "x", "code": "0000-0000-0000-0000-0000"}`, "")
	if code != 400 || out["error"] != msgRecoveryAfterPrimary {
		t.Fatalf("%d %v", code, out)
	}
	e.h.MFA.Gates = fakeGates{}
	if code, _ := e.do(t, nil, "POST", "/login/recovery", `{}`, ""); code != 404 {
		t.Fatalf("recovery off: %d", code)
	}
}
