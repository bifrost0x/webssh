package oidc

import (
	"context"
	"net/http"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
)

type toggleGate struct{ on bool }

func (g *toggleGate) Active(context.Context, string) (bool, error) { return g.on, nil }

// The administrator switches the security feature "oidc" off while a
// redirect is in flight. Python's before_request gate (request_feature_name
// covers every /oidc/ path) answers the callback with 404; the sign-in
// must not finish (RS2-02).
func TestCallbackHonoursFeatureGate(t *testing.T) {
	x := newHarness(t, nil)
	gate := &toggleGate{on: true}
	x.h.Gates = gate
	x.link(t, 1, "subject-1")
	w := x.do(t, "GET", "/oidc/login?next=/files", "b1", principal.Principal{}, "")
	cb := x.redirect(t, authURLOf(t, w))
	gate.on = false
	w = x.do(t, "GET", cb, "b1", principal.Principal{}, "")
	if x.signIn.last != nil || w.Code != http.StatusNotFound {
		t.Fatalf("sign-in finished with the oidc feature off: %d %+v", w.Code, x.signIn.last)
	}
}

// Every route of the Python gate answers 404 with the feature off, also
// for a signed-in administrator.
func TestGatedRoutesAnswerNotFound(t *testing.T) {
	x := newHarness(t, nil)
	x.h.Gates = &toggleGate{on: false}
	admin := principal.Principal{UserID: 1, SessionID: "s1", Username: "admin", IsAdmin: true}
	for _, rt := range []struct{ method, path string }{
		{"GET", "/oidc/login"},
		{"GET", "/oidc/callback?state=x&code=y"},
		{"GET", "/api/account/oidc"},
		{"POST", "/api/account/oidc/link/start"},
		{"GET", "/admin/api/users/2/oidc-identities"},
		{"POST", "/admin/api/users/2/oidc-link"},
		{"DELETE", "/admin/api/users/2/oidc-identities/1"},
	} {
		if w := x.do(t, rt.method, rt.path, "b1", admin, ""); w.Code != http.StatusNotFound {
			t.Errorf("%s %s with oidc off: %d", rt.method, rt.path, w.Code)
		}
	}
}
