package github

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
)

func grant(action principal.Action, target string) map[string]string {
	return map[string]string{StepUpHeader: "grant:" + string(action) + ":" + target}
}

func TestLinkFlow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	uid := e.accounts.add("alice", "")
	p := principal.Principal{UserID: uid, SessionID: "s1", Username: "alice"}
	if rec := e.do("POST", "/api/account/github/link/start", "b1", p, nil, "{}"); rec.Code != http.StatusForbidden ||
		decode(t, rec)["code"] != "step_up_required" {
		t.Fatalf("without grant: %d %s", rec.Code, rec.Body)
	}
	start := e.do("POST", "/api/account/github/link/start", "b1", p, grant(principal.ActionGitHubLink, "1"), "{}")
	cb := e.authorize(start, "octo-alice")
	// Another session of the same account cannot complete it.
	other := p
	other.SessionID = "s2"
	if rec := e.do("GET", cb, "b1", other, nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("other session: %d %s", rec.Code, rec.Body)
	}
	start = e.do("POST", "/api/account/github/link/start", "b1", p, grant(principal.ActionGitHubLink, "1"), "{}")
	cb = e.authorize(start, "octo-alice")
	rec := e.do("GET", cb, "b1", p, nil, "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/security" {
		t.Fatalf("link: %d %s", rec.Code, rec.Body)
	}
	status := decode(t, e.do("GET", "/api/account/github", "b1", p, nil, ""))
	identity, _ := status["identity"].(map[string]any)
	if identity["github_user_id"] != "1001" || identity["login"] != "octo-alice" || identity["display_name"] != "Alice" {
		t.Fatalf("status %v", status)
	}
	if rec := e.do("POST", "/api/account/github/link/start", "b1", p, grant(principal.ActionGitHubLink, "1"), "{}"); rec.Code != http.StatusConflict {
		t.Fatalf("second link: %d", rec.Code)
	}
	// The same GitHub id cannot be linked to another account.
	bob := e.accounts.add("bob", "")
	pb := principal.Principal{UserID: bob, SessionID: "s3", Username: "bob"}
	cb = e.authorize(e.do("POST", "/api/account/github/link/start", "b3", pb, grant(principal.ActionGitHubLink, "2"), "{}"), "octo-alice")
	if rec := e.do("GET", cb, "b3", pb, nil, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), msgAlreadyLinked) {
		t.Fatalf("collision: %d %s", rec.Code, rec.Body)
	}
}

func TestLinkRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	dir := e.accounts.add("dir", "ldap")
	pd := principal.Principal{UserID: dir, SessionID: "s1"}
	if rec := e.do("POST", "/api/account/github/link/start", "b1", pd, grant(principal.ActionGitHubLink, "1"), "{}"); rec.Code != http.StatusConflict {
		t.Fatalf("LDAP account: %d", rec.Code)
	}
	uid := e.accounts.add("alice", "")
	p := principal.Principal{UserID: uid, SessionID: "s2"}
	cb := e.authorize(e.do("POST", "/api/account/github/link/start", "b1", p, grant(principal.ActionGitHubLink, "2"), "{}"), "octo-alice")
	e.accounts.update(uid, func(a *Account) { a.Generation++ })
	if rec := e.do("GET", cb, "b1", p, nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("generation changed: %d", rec.Code)
	}
	cb = e.authorize(e.do("POST", "/api/account/github/link/start", "b1", p, grant(principal.ActionGitHubLink, "2"), "{}"), "octo-alice")
	if rec := e.do("GET", cb, "b1", none, nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("signed out: %d", rec.Code)
	}
}

func TestUnlink(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	local := e.accounts.add("alice", "")
	e.link(local, "1001", false)
	p := principal.Principal{UserID: local, SessionID: "s1", Username: "alice"}
	if rec := e.do("DELETE", "/api/account/github", "b1", p, nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("without grant: %d", rec.Code)
	}
	if rec := e.do("DELETE", "/api/account/github", "b1", p, grant(principal.ActionGitHubUnlink, "1"), ""); rec.Code != http.StatusOK || e.signIn.renewed != 1 {
		t.Fatalf("unlink: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("DELETE", "/api/account/github", "b1", p, grant(principal.ActionGitHubUnlink, "1"), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("again: %d", rec.Code)
	}

	gh := e.accounts.add("octo", "github")
	e.link(gh, "1002", true)
	pg := principal.Principal{UserID: gh, SessionID: "s2", Username: "octo"}
	g := grant(principal.ActionGitHubUnlink, "2")
	if rec := e.do("DELETE", "/api/account/github", "b2", pg, g, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), msgNeedPasskey) {
		t.Fatalf("without passkey: %d %s", rec.Code, rec.Body)
	}
	e.passkeys[gh] = 1
	if rec := e.do("DELETE", "/api/account/github", "b2", pg, g, ""); rec.Code != http.StatusOK {
		t.Fatalf("with passkey: %d %s", rec.Code, rec.Body)
	}
	if e.accounts.get(gh).Managed != "" {
		t.Fatal("provisioned account still GitHub-managed")
	}

	listed := e.accounts.add("cfgadmin", "github")
	e.link(listed, "1003", true)
	e.passkeys[listed] = 1
	pl := principal.Principal{UserID: listed, SessionID: "s3", Username: "cfgadmin"}
	if rec := e.do("DELETE", "/api/account/github", "b3", pl, grant(principal.ActionGitHubUnlink, "3"), ""); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "ADMIN_USERS") {
		t.Fatalf("ADMIN_USERS account: %d %s", rec.Code, rec.Body)
	}
}

func TestStepUpStartAlwaysRefuses(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.configure(nil)
	p := principal.Principal{UserID: 1, SessionID: "s1"}
	if rec := e.do("POST", "/api/account/step-up/github/start", "b1", p, nil, `{"intent":"x"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("start: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/account/step-up/github/start", "b1", p, nil, `[1]`); rec.Code != http.StatusBadRequest {
		t.Fatalf("not an object: %d", rec.Code)
	}
}

func TestAdminConfiguration(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	admin := principal.Principal{UserID: 1, SessionID: "s1", IsAdmin: true, Username: "admin"}
	user := principal.Principal{UserID: 2, SessionID: "s2"}
	if rec := e.do("GET", "/admin/api/github-auth/config", "b1", user, nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", rec.Code)
	}
	cfg := decode(t, e.do("GET", "/admin/api/github-auth/config", "b1", admin, nil, ""))["configuration"].(map[string]any)
	if cfg["enabled"] != false || cfg["generation"] != float64(0) || cfg["error"] != nil {
		t.Fatalf("empty configuration %v", cfg)
	}
	g := grant(principal.ActionGitHubConfig, "global")
	if rec := e.do("POST", "/admin/api/github-auth/config", "b1", admin, nil, `{"enabled": false}`); rec.Code != http.StatusForbidden {
		t.Fatalf("without grant: %d", rec.Code)
	}
	body := `{"enabled": true, "client_id": "` + e.gh.clientID + `", "client_secret": "` + e.gh.clientSecret +
		`", "redirect_uri": " ` + testRedirect + ` ", "allowed_orgs": " Lab-Org , lab-org,other ", "auto_provision": false}`
	rec := e.do("POST", "/admin/api/github-auth/config", "b1", admin, g, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	cfg = decode(t, rec)["configuration"].(map[string]any)
	if cfg["active"] != true || cfg["client_secret_configured"] != true || cfg["generation"] != float64(2) ||
		cfg["redirect_uri"] != testRedirect || len(cfg["allowed_orgs"].([]any)) != 2 || strings.Contains(rec.Body.String(), e.gh.clientSecret) {
		t.Fatalf("configuration %s", rec.Body)
	}
	for _, bad := range []string{`{}`, `[]`, `{"unknown": 1}`, `{"enabled": "yes"}`, `{"client_id": "short"}`,
		`{"client_secret": "too-short"}`, `{"client_secret": "` + strings.Repeat("a", 30) + `\n"}`,
		`{"redirect_uri": "http://ssh.example.test/auth/github/callback"}`, `{"allowed_orgs": ["-bad"]}`,
		`{"allowed_orgs": [1]}`, `{"clear_client_secret": true}`, `{"clear_client_secret": 1}`} {
		if rec := e.do("POST", "/admin/api/github-auth/config", "b1", admin, g, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	// Refused updates changed nothing.
	cfg = decode(t, e.do("GET", "/admin/api/github-auth/config", "b1", admin, nil, ""))["configuration"].(map[string]any)
	if cfg["generation"] != float64(2) || cfg["active"] != true {
		t.Fatalf("after refusals %v", cfg)
	}
	// Turning sign-in off may clear the secret.
	if rec := e.do("POST", "/admin/api/github-auth/config", "b1", admin, g, `{"enabled": false, "clear_client_secret": true}`); rec.Code != http.StatusOK ||
		decode(t, rec)["configuration"].(map[string]any)["client_secret_configured"] != false {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
}
