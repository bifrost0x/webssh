package accounts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type fakeGates map[string]bool

func (g fakeGates) Active(_ context.Context, f string) (bool, error) { return g[f], nil }

type adminCase struct {
	h    *HTTP
	step *principaltest.StepUp
	l    lifecycle
}

func newAdminCase(t *testing.T) adminCase {
	t.Helper()
	l := newLifecycle(t, "cfg")
	l.s.Factors = &fakeFactors{}
	l.s.Recovery = &fakeRecovery{}
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 3, "cfg", true, false, ManagedLocal, "x")
	step := &principaltest.StepUp{}
	return adminCase{h: &HTTP{Accounts: l.s, StepUp: step, Gates: fakeGates{"recovery": true}, Enabled: true}, step: step, l: l}
}

func (c adminCase) do(t *testing.T, p *principal.Principal, method, path, body, grant string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	c.h.Register(mux)
	c.h.RegisterAdmin(mux)
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if p != nil {
		r = r.WithContext(principal.With(r.Context(), *p))
	}
	if grant != "" {
		r.Header.Set(StepUpHeader, grant)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func TestAdminActionsHTTP(t *testing.T) {
	t.Parallel()
	c := newAdminCase(t)
	admin := principaltest.Admin(1)
	user := principaltest.User(2)
	for _, x := range []struct {
		method, path, action, target, body string
		status                             int
		contains                           string
	}{
		// The grant is checked first, even for an unknown account or action.
		{"POST", "/admin/api/users/9/lock", "user.manage", "", "", 403, "step_up_required"},
		{"POST", "/admin/api/users/9/lock", "user.manage", "9:lock", "", 404, "User not found"},
		{"POST", "/admin/api/users/2/explode", "user.manage", "2:explode", "", 400, "Unknown action"},
		{"POST", "/admin/api/users/1/lock", "user.manage", "1:lock", "", 400, "You cannot lock your own account"},
		{"POST", "/admin/api/users/3/demote", "user.manage", "3:demote", "", 409, "ADMIN_USERS"},
		{"POST", "/admin/api/users/2/lock", "user.manage", "2:lock", "", 200, `"is_locked":true`},
		{"POST", "/admin/api/users/2/unlock", "user.manage", "2:unlock", "", 200, `"is_locked":false`},
		{"POST", "/admin/api/users/2/promote", "user.manage", "2:promote", "", 200, `"is_admin":true`},
		{"POST", "/admin/api/users/3/promote", "user.manage", "3:promote", "", 200, `"admin_managed_by_config":true`},
		{"POST", "/admin/api/users/abc/lock", "", "", "", 404, ""},
		{"POST", "/admin/api/users/-2/lock", "", "", "", 404, ""},
		{"DELETE", "/admin/api/users/2/mfa", "user.mfa_reset", "2", `[]`, 400, "Invalid request"},
		{"DELETE", "/admin/api/users/2/mfa", "user.mfa_reset", "2", `{"confirm_username": "Bob"}`, 400, "Target confirmation does not match"},
		{"DELETE", "/admin/api/users/2/mfa", "user.mfa_reset", "2", `{"confirm_username": ["bob"]}`, 400, "Target confirmation does not match"},
		{"DELETE", "/admin/api/users/9/mfa", "user.mfa_reset", "9", `{}`, 404, "User not found"},
		{"DELETE", "/admin/api/users/2/mfa", "user.mfa_reset", "2", `{"confirm_username": "bob"}`, 200, `"ok":true`},
		{"POST", "/admin/api/users/2/recovery", "recovery.reset", "2", `not json`, 400, "Target confirmation does not match"},
		{"POST", "/admin/api/users/2/recovery", "recovery.reset", "2", `{"confirm_username": "bob"}`, 200, `"codes":[`},
		{"POST", "/admin/api/users/2/delete", "user.manage", "2:delete", "", 200, `"ok":true`},
	} {
		if x.target != "" {
			c.step.Issue(admin, principal.Action(x.action), x.target, "g")
		}
		rec := c.do(t, &admin, x.method, x.path, x.body, "g")
		if rec.Code != x.status || !strings.Contains(rec.Body.String(), x.contains) {
			t.Errorf("%s %s (%s): %d %s", x.method, x.path, x.target, rec.Code, rec.Body)
		}
		if rec.Header().Get("Cache-Control") != "no-store" && rec.Code != 404 {
			t.Errorf("%s: no Cache-Control", x.path)
		}
	}
	if rec := c.do(t, &user, "POST", "/admin/api/users/3/lock", "", "g"); rec.Code != 403 {
		t.Fatalf("non-admin %d", rec.Code)
	}
	c.h.Enabled = false
	if rec := c.do(t, &admin, "POST", "/admin/api/users/3/lock", "", "g"); rec.Code != 404 {
		t.Fatalf("disabled panel %d", rec.Code)
	}
}

func TestRecoveryResetNeedsTheFeature(t *testing.T) {
	t.Parallel()
	c := newAdminCase(t)
	c.h.Gates = fakeGates{}
	admin := principaltest.Admin(1)
	c.step.Issue(admin, principal.ActionRecoveryReset, "2", "g")
	if rec := c.do(t, &admin, "POST", "/admin/api/users/2/recovery", `{"confirm_username": "bob"}`, "g"); rec.Code != 404 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// The grant was spent before the feature check, as in the Python release.
	if calls := c.step.Calls(); len(calls) != 1 || calls[0].Err != nil {
		t.Fatalf("%+v", calls)
	}
	if c.l.s.Recovery.(*fakeRecovery).calls != 0 {
		t.Fatal("codes replaced while the feature is off")
	}
}
