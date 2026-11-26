package httpapi

import (
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
)

// Every area has a name, an owner and its own variables; an area that is
// complete has no preview routes left and stays in the list until FE1
// removes the catalog (M2 plan, guideline 3).
func TestAreasAreWellFormed(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, a := range areas {
		if a.name == "" || a.owner == "" || seen[a.name] {
			t.Errorf("area %+v: empty or repeated name or owner", a.name)
		}
		seen[a.name] = true
		for _, rt := range a.built {
			if rt.access == 0 || rt.access == AccessPreview {
				t.Errorf("area %s: built route %s has no access level", a.name, rt.pattern)
			}
		}
	}
}

// The callback and sign-in paths of the external providers are invariant
// I-03: they are in the catalog, as GET routes, whether built or not.
func TestExternalSignInPathsAreInTheCatalog(t *testing.T) {
	t.Parallel()
	var all []string
	for _, rt := range catalogRoutes() {
		all = append(all, rt.pattern)
	}
	all = append(all, previewRoutes()...)
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
