package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// The upgrade notice through the whole server: reading and acknowledging
// need a session, the acknowledgement needs the CSRF token and a
// same-origin request, it acts on the signed-in account only, and it
// holds across a restart.
func TestUpgradeNoticeThroughTheServer(t *testing.T) {
	env := backupEnv(t)
	sys, ts, stop := openEnv(t, env)
	signUp(t, ts.URL, "admin1", "first-password-1")
	ids := map[string]int64{}
	for _, name := range []string{"alice", "bob"} {
		acc, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: name, Password: name + "-password-1", ByAdmin: true})
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = acc.ID
		if err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
			return settings.GrantNotice(t.Context(), tx, acc.ID, settings.NoticeUpgrade)
		}); err != nil {
			t.Fatal(err)
		}
	}
	const pendingBody, noneBody = `{"notices":["upgrade-3.4"]}`, `{"notices":[]}`
	const ackPath = "/api/account/notices/acknowledge"
	notices := func(c *http.Client, base string) string {
		t.Helper()
		resp, body := get(t, c, base+"/api/account/notices")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("notices: %d %s", resp.StatusCode, body)
		}
		return body
	}
	post := func(c *http.Client, origin, csrf string) int {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+ackPath, strings.NewReader(`{"notice":"upgrade-3.4"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		if csrf != "" {
			req.Header.Set("X-CSRFToken", csrf)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	alice := signIn(t, ts.URL, "alice", "alice-password-1")
	bob := signIn(t, ts.URL, "bob", "bob-password-1")
	if got := notices(alice, ts.URL); got != pendingBody {
		t.Fatalf("alice: %s", got)
	}
	anon := &http.Client{}
	if resp, _ := get(t, anon, ts.URL+"/api/account/notices"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous read: %d", resp.StatusCode)
	}
	if status := post(anon, ts.URL, ""); status != http.StatusUnauthorized {
		t.Errorf("anonymous acknowledgement: %d", status)
	}
	_, page := get(t, alice, ts.URL+"/security")
	m := csrfMeta.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no CSRF meta tag on /security")
	}
	for name, status := range map[string]int{
		"without the CSRF token":  post(alice, ts.URL, ""),
		"with a wrong CSRF token": post(alice, ts.URL, m[1]+"x"),
		"from another site":       post(alice, "https://attacker.example", m[1]),
	} {
		if status < 400 || status >= 500 {
			t.Errorf("acknowledgement %s: %d", name, status)
		}
	}
	if got := notices(alice, ts.URL); got != pendingBody {
		t.Fatalf("a refused acknowledgement changed the notice: %s", got)
	}
	if status, body := apiCall(t, alice, ts.URL, http.MethodPost, ackPath,
		map[string]any{"notice": settings.NoticeUpgrade, "user_id": ids["bob"]}, ""); status != http.StatusBadRequest {
		t.Fatalf("a body naming bob: %d %s", status, body)
	}
	if status, body := apiCall(t, alice, ts.URL, http.MethodPost, ackPath, map[string]string{"notice": settings.NoticeUpgrade}, ""); status != http.StatusOK || body != noneBody {
		t.Fatalf("acknowledgement: %d %s", status, body)
	}
	if got := notices(alice, ts.URL); got != noneBody {
		t.Fatalf("alice after the acknowledgement: %s", got)
	}
	if got := notices(bob, ts.URL); got != pendingBody {
		t.Fatalf("alice's acknowledgement reached bob: %s", got)
	}
	// Another device of alice does not see it either.
	if got := notices(signIn(t, ts.URL, "alice", "alice-password-1"), ts.URL); got != noneBody {
		t.Fatalf("alice on a second device: %s", got)
	}

	stop()
	_, ts2, _ := openEnv(t, env)
	if got := notices(signIn(t, ts2.URL, "alice", "alice-password-1"), ts2.URL); got != noneBody {
		t.Fatalf("alice after a restart: %s", got)
	}
	if got := notices(signIn(t, ts2.URL, "bob", "bob-password-1"), ts2.URL); got != pendingBody {
		t.Fatalf("bob after a restart: %s", got)
	}
}
