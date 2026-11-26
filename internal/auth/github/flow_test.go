package github

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

var none principal.Principal

func (e *env) link(userID int64, githubID string, provisioned bool) {
	e.t.Helper()
	err := e.svc.DB.Write(e.t.Context(), func(tx *store.Tx) error {
		i := e.svc.newIdentity(userID, Profile{UserID: githubID, Login: "x"}, provisioned)
		_, err := insertTx(e.t.Context(), tx, i)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func TestInactiveRoutesAnswer404(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, path := range []string{"/auth/github/login", "/auth/github/callback?code=a&state=b"} {
		if rec := e.do("GET", path, "b1", none, nil, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

func TestLoginLinkedAccount(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	uid := e.accounts.add("alice", "")
	e.link(uid, "1001", false)
	start := e.do("GET", "/auth/github/login?next=/hosts", "b1", none, nil, "")
	if start.Code != http.StatusFound {
		t.Fatalf("login: %d %s", start.Code, start.Body)
	}
	cb := e.authorize(start, "octo-alice")
	rec := e.do("GET", cb, "b1", none, nil, "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/hosts" || len(e.signIn.signed) != 1 || e.signIn.signed[0] != uid {
		t.Fatalf("callback: %d %q %v", rec.Code, rec.Header().Get("Location"), e.signIn.signed)
	}
	i, _, _ := e.svc.Identity(t.Context(), uid)
	if i.Login != "octo-alice" || i.DisplayName != "Alice" || !i.LastVerifiedAt.Equal(e.now) {
		t.Fatalf("identity not refreshed: %+v", i)
	}
	// The state is spent: a replay finds nothing.
	if again := e.do("GET", cb, "b1", none, nil, ""); again.Code != http.StatusBadRequest {
		t.Fatalf("replay: %d", again.Code)
	}
}

func TestCallbackRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	uid := e.accounts.add("alice", "")
	e.link(uid, "1001", false)
	cases := []struct {
		name   string
		mutate func(cb string) (string, string) // callback, binding
		status int
	}{
		{"other browser", func(cb string) (string, string) { return cb, "b2" }, http.StatusBadRequest},
		{"no binding", func(cb string) (string, string) { return cb, "" }, http.StatusBadRequest},
		{"foreign state", func(cb string) (string, string) {
			return strings.Replace(cb, "state=", "state=x", 1), "b1"
		}, http.StatusBadRequest},
		{"repeated state", func(cb string) (string, string) { return cb + "&state=zzz", "b1" }, http.StatusBadRequest},
		{"provider error", func(cb string) (string, string) { return cb + "&error=access_denied", "b1" }, http.StatusBadRequest},
		{"wrong code", func(cb string) (string, string) {
			return strings.Replace(cb, "code=", "code=bad", 1), "b1"
		}, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		start := e.do("GET", "/auth/github/login", "b1", none, nil, "")
		cb, binding := tc.mutate(e.authorize(start, "octo-alice"))
		if rec := e.do("GET", cb, binding, none, nil, ""); rec.Code != tc.status {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body)
		}
	}
	if len(e.signIn.signed) != 0 {
		t.Fatalf("signed in: %v", e.signIn.signed)
	}
}

func TestCallbackExpiredAndReconfigured(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	uid := e.accounts.add("alice", "")
	e.link(uid, "1001", false)
	cb := e.authorize(e.do("GET", "/auth/github/login", "b1", none, nil, ""), "octo-alice")
	e.now = e.now.Add(5*time.Minute + time.Second)
	if rec := e.do("GET", cb, "b1", none, nil, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired: %d", rec.Code)
	}
	cb = e.authorize(e.do("GET", "/auth/github/login", "b1", none, nil, ""), "octo-alice")
	e.configure(map[string]any{"allowed_orgs": []string{}})
	if rec := e.do("GET", cb, "b1", none, nil, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("after a configuration change: %d", rec.Code)
	}
}

func TestUnlinkedIdentityAndProvisioning(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	login := func(user string) (int, string) {
		cb := e.authorize(e.do("GET", "/auth/github/login", "b1", none, nil, ""), user)
		rec := e.do("GET", cb, "b1", none, nil, "")
		return rec.Code, rec.Body.String()
	}
	if code, body := login("octo-carol"); code != http.StatusForbidden || !strings.Contains(body, msgNotLinked) {
		t.Fatalf("unlinked: %d %s", code, body)
	}
	e.configure(map[string]any{"auto_provision": true})
	e.accounts.add("octo_carol", "")
	if code, body := login("octo-carol"); code != http.StatusFound {
		t.Fatalf("provision: %d %s", code, body)
	}
	id, err := e.svc.Account(t.Context(), identityFor("1003"))
	if err != nil {
		t.Fatal(err)
	}
	acc := e.accounts.get(id)
	if acc.Username != "octo_carol_gh1003" || acc.Managed != "github" {
		t.Fatalf("provisioned %+v", acc)
	}
	i, _, _ := e.svc.Identity(t.Context(), id)
	if !i.Provisioned {
		t.Fatal("identity not marked provisioned")
	}
	// A second sign-in uses the same account.
	if code, _ := login("octo-carol"); code != http.StatusFound || e.signIn.signed[1] != id {
		t.Fatalf("second sign-in: %d %v", code, e.signIn.signed)
	}
}

func TestProductionNeedsOrganizationsForProvisioning(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.Production = true
	if _, err := e.svc.Update(t.Context(), []byte(`{"auto_provision": true}`), 1); err == nil {
		t.Fatal("production accepted unrestricted provisioning")
	}
	e.configure(map[string]any{"auto_provision": true, "allowed_orgs": "lab-org"})
	cb := e.authorize(e.do("GET", "/auth/github/login", "b1", none, nil, ""), "octo-alice")
	if rec := e.do("GET", cb, "b1", none, nil, ""); rec.Code != http.StatusFound {
		t.Fatalf("member: %d %s", rec.Code, rec.Body)
	}
	cb = e.authorize(e.do("GET", "/auth/github/login", "b1", none, nil, ""), "octo-bob")
	if rec := e.do("GET", cb, "b1", none, nil, ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgOrgRequired) {
		t.Fatalf("pending member: %d %s", rec.Code, rec.Body)
	}
	// Settings stored before the rule existed fail closed.
	if err := e.svc.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE authgithub_config SET allowed_orgs = '[]'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cb = e.authorize(e.do("GET", "/auth/github/login", "b1", none, nil, ""), "octo-carol")
	if rec := e.do("GET", cb, "b1", none, nil, ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgNotLinked) {
		t.Fatalf("legacy unrestricted: %d %s", rec.Code, rec.Body)
	}
}

func TestInactiveAccountsAreRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	locked := e.accounts.add("alice", "")
	e.accounts.update(locked, func(a *Account) { a.Locked = true })
	e.link(locked, "1001", false)
	dir := e.accounts.add("carol", "ldap")
	e.link(dir, "1003", false)
	for _, user := range []string{"octo-alice", "octo-carol"} {
		cb := e.authorize(e.do("GET", "/auth/github/login", "b1", none, nil, ""), user)
		if rec := e.do("GET", cb, "b1", none, nil, ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgInactive) {
			t.Errorf("%s: %d %s", user, rec.Code, rec.Body)
		}
	}
	e.signIn.noMFA = true
	free := e.accounts.add("bob", "")
	e.link(free, "1002", false)
	cb := e.authorize(e.do("GET", "/auth/github/login", "b1", none, nil, ""), "octo-bob")
	if rec := e.do("GET", cb, "b1", none, nil, ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgNoLocalMFA) {
		t.Fatalf("MFA without local factor: %d %s", rec.Code, rec.Body)
	}
}

func TestLoginRateLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	e.svc.Limits = limits()
	for i := range 6 {
		rec := e.do("GET", "/auth/github/login", "b1", none, nil, "")
		if want := http.StatusFound; i < 5 && rec.Code != want || i == 5 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
}

func identityFor(githubID string) auth.Identity {
	return auth.Identity{Provider: auth.ProviderGitHub, Subject: githubID}
}

func limits() auth.FactorLimits {
	return auth.FactorLimits{Limiter: auth.NewLimiter(), Enabled: true, ClientAddr: func(*http.Request) string { return "192.0.2.1" }}
}
