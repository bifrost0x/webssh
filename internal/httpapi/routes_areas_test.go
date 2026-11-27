package httpapi

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
)

// Every area has a name, an owner and routes with an access level.
func TestAreasAreWellFormed(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, a := range areas {
		if a.name == "" || a.owner == "" || seen[a.name] {
			t.Errorf("area %+v: empty or repeated name or owner", a.name)
		}
		seen[a.name] = true
		for _, rt := range a.built {
			if rt.access == 0 || rt.access == AccessGone {
				t.Errorf("area %s: built route %s has no access level", a.name, rt.pattern)
			}
		}
	}
}

// The callback and sign-in paths of the external providers are invariant
// I-03: they are in the catalog.
func TestExternalSignInPathsAreInTheCatalog(t *testing.T) {
	t.Parallel()
	var all []string
	for _, rt := range catalogRoutes() {
		all = append(all, rt.pattern)
	}
	for _, want := range []string{
		"GET " + auth.PathOIDCLogin, "GET " + auth.PathOIDCCallback,
		"GET " + auth.PathGitHubLogin, "GET " + auth.PathGitHubCallback,
		"POST " + auth.PathLDAPLogin,
	} {
		if !slices.Contains(all, want) {
			t.Errorf("%s is not in the route catalog", want)
		}
	}
	if auth.PathOIDCCallback != "/oidc/callback" || auth.PathGitHubCallback != "/auth/github/callback" {
		t.Error("a callback path changed; it is registered at the identity providers (I-03)")
	}
	for _, p := range []string{auth.PathOIDCCallback, auth.PathGitHubCallback} {
		if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
			t.Errorf("callback path %q is not a clean absolute path", p)
		}
	}
}

// A disabled area answers 404 and is not reported as unwired; a route
// the area shares keeps its handler.
func TestDisableArea(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("POST /api/account/step-up/status", echo)
	if err := e.h.DisableArea("oidc"); err != nil {
		t.Fatal(err)
	}
	if err := e.h.DisableArea("nothing"); err == nil {
		t.Fatal("an unknown area was disabled")
	}
	filled, err := e.h.Finish()
	if err != nil {
		t.Fatal(err)
	}
	for _, rt := range oidcBuilt {
		if slices.Contains(filled, rt.pattern) {
			t.Errorf("%s of the disabled area is reported as unwired", rt.pattern)
		}
	}
	if w := e.do(req{target: "/oidc/login"}); w.Code != http.StatusNotFound {
		t.Errorf("/oidc/login: %d, want 404", w.Code)
	}
	binding, token := e.csrf("s-alice")
	w := e.do(req{method: http.MethodPost, target: "/api/account/step-up/status", token: "tok-alice", binding: binding,
		headers: map[string]string{"X-CSRFToken": token}})
	if w.Code != http.StatusOK {
		t.Errorf("shared route: %d, want its own handler", w.Code)
	}
}
