package ldap

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

func identityFor(provider, subject string) auth.Identity {
	return auth.Identity{Provider: auth.ProviderLDAP, Issuer: provider, Subject: subject}
}

var admin = principaltest.Admin(1)

func (f *fixture) serve(t *testing.T, method, target, body, grant string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	(&HTTP{Service: f.svc, AdminPanel: true}).Register(mux)
	r := httptest.NewRequestWithContext(principal.With(t.Context(), admin), method, target, strings.NewReader(body))
	if grant != "" {
		r.Header.Set(auth.StepUpHeader, grant)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]jsontext.Value {
	t.Helper()
	var m map[string]jsontext.Value
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return m
}

func TestAdminLink(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.accounts.add(Account{ID: 5, Username: "erin"})
	f.dir.add("erin.dir", "uuid-e", "pw")
	f.stepup.Issue(admin, principal.ActionLDAPLink, "5", "g1")
	w := f.serve(t, "POST", "/admin/api/users/5/ldap-link", `{"confirm_username":"erin","directory_username":" erin.dir "}`, "g1")
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	row, found, _ := f.svc.IdentityOf(t.Context(), 5)
	if !found || row.DirectoryUsername != "erin.dir" || row.Subject != "uuid-e" || string(decode(t, w)["id"]) != "1" {
		t.Fatalf("identity %+v", row)
	}
	acc := f.accounts.get(5)
	if acc.Managed != "ldap" || acc.Generation != 1 || len(f.oidc.removed) != 1 || f.sessions.count(5) != 1 {
		t.Fatalf("account not adopted: %+v %v", acc, f.oidc.removed)
	}
	// The grant is spent: the same request is refused.
	if w := f.serve(t, "POST", "/admin/api/users/5/ldap-link", `{}`, "g1"); w.Code != http.StatusForbidden {
		t.Fatalf("reused grant: %d", w.Code)
	}
}

func TestAdminLinkRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		setup  func(f *fixture)
		user   string
		body   string
		status int
		text   string
	}{
		"no such account":     {user: "99", body: `{"confirm_username":"x","directory_username":"erin.dir"}`, status: 404, text: "User not found"},
		"administrator":       {user: "1", body: `{"confirm_username":"root","directory_username":"erin.dir"}`, status: 400, text: "break-glass"},
		"confirmation":        {body: `{"confirm_username":"ERIN","directory_username":"erin.dir"}`, status: 400, text: "confirmation"},
		"name not a string":   {body: `{"confirm_username":"erin","directory_username":5}`, status: 400, text: "Directory username is required"},
		"name blank":          {body: `{"confirm_username":"erin","directory_username":"  "}`, status: 400, text: "Directory username is required"},
		"name too long":       {body: `{"confirm_username":"erin","directory_username":"` + strings.Repeat("a", 257) + `"}`, status: 400, text: "required"},
		"not an object":       {body: `[1]`, status: 400, text: "Invalid request"},
		"too large":           {body: `{"x":"` + strings.Repeat("a", 5000) + `"}`, status: 413, text: "too large"},
		"not found uniquely":  {body: `{"confirm_username":"erin","directory_username":"nobody"}`, status: 400, text: "uniquely"},
		"directory down":      {setup: func(f *fixture) { f.dir.down = true }, body: `{"confirm_username":"erin","directory_username":"erin.dir"}`, status: 503, text: "temporarily unavailable"},
		"github managed":      {setup: func(f *fixture) { f.accounts.accounts[5].Managed = "github" }, body: `{"confirm_username":"erin","directory_username":"erin.dir"}`, status: 409, text: "GitHub"},
		"already linked":      {setup: func(f *fixture) { f.linkUser(t, 5, "erin", "uuid-x", "pw") }, body: `{"confirm_username":"erin","directory_username":"erin.dir"}`, status: 409, text: "already has"},
		"binding of another":  {setup: func(f *fixture) { f.linkUser(t, 6, "frank", "uuid-e", "pw") }, body: `{"confirm_username":"erin","directory_username":"erin.dir"}`, status: 409, text: "already linked"},
		"malformed path":      {user: "05", body: `{}`, status: 404},
		"bad body, no grant":  {body: `[`, status: 403, text: "step_up_required"},
		"grant of other user": {user: "6", body: `{}`, status: 403},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.accounts.add(Account{ID: 5, Username: "erin"})
			f.dir.add("erin.dir", "uuid-e", "pw")
			if tc.setup != nil {
				tc.setup(f)
			}
			user := tc.user
			if user == "" {
				user = "5"
			}
			grant := "g"
			if !strings.Contains(name, "no grant") {
				target := user
				if name == "grant of other user" {
					target = "5"
				}
				f.stepup.Issue(admin, principal.ActionLDAPLink, target, grant)
			} else {
				grant = ""
			}
			w := f.serve(t, "POST", "/admin/api/users/"+user+"/ldap-link", tc.body, grant)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.text) {
				t.Fatalf("status %d %s", w.Code, w.Body)
			}
			if tc.status != 403 && tc.status != 404 || name == "no such account" {
				if calls := f.stepup.Calls(); len(calls) != 1 || calls[0].Err != nil {
					t.Fatalf("the grant must be consumed first: %+v", calls)
				}
			}
		})
	}
}

func TestAdminUnlink(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	row, _, _ := f.svc.IdentityOf(t.Context(), 7)
	target := "/admin/api/users/7/ldap-identities/1"
	f.stepup.Issue(admin, principal.ActionLDAPUnlink, "7:1", "g")
	if w := f.serve(t, "DELETE", target, `{"confirm_username":"alice","new_password":"short"}`, "g"); w.Code != 400 || !strings.Contains(w.Body.String(), "New password must be at least 8") {
		t.Fatalf("short password: %d %s", w.Code, w.Body)
	}
	f.stepup.Issue(admin, principal.ActionLDAPUnlink, "7:1", "g")
	if w := f.serve(t, "DELETE", target, `{"confirm_username":"alice","new_password":"long enough"}`, "g"); w.Code != 200 {
		t.Fatalf("unlink: %d %s", w.Code, w.Body)
	}
	if _, found, _ := f.svc.IdentityOf(t.Context(), 7); found || f.accounts.released[7] != "hash:long enough" || f.sessions.count(7) != 1 {
		t.Fatalf("not released (identity %d)", row.ID)
	}
	if required, checked := f.revalidation(t, 7); required || !checked.IsZero() {
		t.Fatal("revalidation state not dropped")
	}
}

func TestAdminUnlinkRefusals(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		user, identity, body string
		status               int
		text                 string
	}{
		"config admin":   {user: "7", identity: "1", body: `{"confirm_username":"root","new_password":"long enough"}`, status: 409, text: "ADMIN_USERS"},
		"other identity": {user: "7", identity: "2", body: `{"confirm_username":"alice","new_password":"long enough"}`, status: 404, text: "LDAP identity not found"},
		"confirmation":   {user: "7", identity: "1", body: `{"confirm_username":"bob","new_password":"long enough"}`, status: 400, text: "confirmation"},
		"no password":    {user: "7", identity: "1", body: `{"confirm_username":"alice","new_password":null}`, status: 400, text: "New password is required"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
			if name == "config admin" {
				f.accounts.accounts[7].Username = "root"
			}
			f.stepup.Issue(admin, principal.ActionLDAPUnlink, tc.user+":"+tc.identity, "g")
			w := f.serve(t, "DELETE", "/admin/api/users/"+tc.user+"/ldap-identities/"+tc.identity, tc.body, "g")
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.text) {
				t.Fatalf("status %d %s", w.Code, w.Body)
			}
			if _, found, _ := f.svc.IdentityOf(t.Context(), 7); !found {
				t.Fatal("identity removed")
			}
		})
	}
}

func TestAdminIdentityAndStatus(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.accounts.add(Account{ID: 5, Username: "erin"})
	if w := f.serve(t, "GET", "/admin/api/users/5/ldap-identity", "", ""); w.Code != 200 || w.Body.String() != `{"identity":null}` {
		t.Fatalf("no identity: %d %s", w.Code, w.Body)
	}
	if w := f.serve(t, "GET", "/admin/api/users/9/ldap-identity", "", ""); w.Code != 404 {
		t.Fatalf("missing account: %d", w.Code)
	}
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	w := f.serve(t, "GET", "/admin/api/users/7/ldap-identity", "", "")
	want := `{"identity":{"id":1,"provider":"corp","directory_username":"alice","created_at":"2026-11-27T10:00:00","last_verified_at":null}}`
	if w.Code != 200 || w.Body.String() != want {
		t.Fatalf("identity: %d %s", w.Code, w.Body)
	}
	if w := f.serve(t, "GET", "/admin/api/ldap/status", "", ""); w.Code != 200 ||
		w.Body.String() != `{"enabled":true,"provider":"corp","ready":true,"transport":"ldap+StartTLS"}` {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	f.dir.down = true
	if w := f.serve(t, "GET", "/admin/api/ldap/status", "", ""); w.Code != 503 || !strings.Contains(w.Body.String(), `"ready":false`) {
		t.Fatalf("status down: %d %s", w.Code, w.Body)
	}
}

func TestAdminRoutesHidden(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.svc.Gates = gates{off: true}
	for _, path := range []string{"/admin/api/ldap/status", "/admin/api/users/1/ldap-identity"} {
		if w := f.serve(t, "GET", path, "", ""); w.Code != 404 {
			t.Fatalf("%s with LDAP inactive: %d", path, w.Code)
		}
	}
	mux := http.NewServeMux()
	(&HTTP{Service: newFixture(t).svc}).Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequestWithContext(principal.With(t.Context(), admin), "GET", "/admin/api/ldap/status", nil))
	if w.Code != 404 {
		t.Fatalf("without the admin panel: %d", w.Code)
	}
	mux = http.NewServeMux()
	(&HTTP{Service: newFixture(t).svc, AdminPanel: true}).Register(mux)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequestWithContext(principal.With(t.Context(), principaltest.User(3)), "GET", "/admin/api/ldap/status", nil))
	if w.Code != 403 {
		t.Fatalf("non-admin: %d", w.Code)
	}
	if !fault.Is(errStatusLimited, fault.RateLimited) {
		t.Fatal("status limit code")
	}
}
