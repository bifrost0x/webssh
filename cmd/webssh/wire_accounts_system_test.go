package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/store"
)

var csrfMeta = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)">`)

// signIn signs in with the password form and returns the client.
func signIn(t *testing.T, base, user, password string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	_, page := get(t, c, base+"/login")
	m := csrfField.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no CSRF token on /login")
	}
	form := url.Values{"username": {user}, "password": {password}, "csrf_token": {m[1]}}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return c
}

// apiCall sends a JSON request with the CSRF token of the client's page.
func apiCall(t *testing.T, c *http.Client, base, method, path string, body any, grant string) (int, string) {
	t.Helper()
	_, page := get(t, c, base+"/security")
	m := csrfMeta.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no CSRF meta tag on /security")
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(t.Context(), method, base+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	req.Header.Set("X-CSRFToken", m[1])
	if grant != "" {
		req.Header.Set(accounts.StepUpHeader, grant)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func adminGrant(t *testing.T, c *http.Client, base, action, target, password string) string {
	t.Helper()
	status, body := apiCall(t, c, base, http.MethodPost, "/api/step-up/password",
		map[string]string{"action": action, "target": target, "password": password}, "")
	var out struct {
		Grant string `json:"grant"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || out.Grant == "" {
		t.Fatalf("step-up %s %s: %d %s", action, target, status, body)
	}
	return out.Grant
}

// The account administration works through the whole server: a lock ends
// the other account's browser session at once, and a deletion removes
// every row the account owns.
func TestAccountAdministrationThroughTheServer(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{"ADMIN_PANEL_ENABLED": "true"})
	admin := signUp(t, ts.URL, "admin1", "first-password-1")
	bobAcc, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "bob", Password: "bob-password-1", ByAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	bob := signIn(t, ts.URL, "bob", "bob-password-1")
	if resp, _ := get(t, bob, ts.URL+"/api/account/sessions"); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob not signed in: %d", resp.StatusCode)
	}
	base, _ := url.Parse(ts.URL)
	known := false
	for _, ck := range bob.Jar.Cookies(base) {
		known = known || ck.Name == "session_device" && strings.HasPrefix(ck.Value, "v1.")
	}
	if !known {
		t.Fatal("the password sign-in set no known-device cookie")
	}
	if _, err := sys.recovery.Generate(t.Context(), bobAcc.ID); err != nil {
		t.Fatal(err)
	}

	if status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/users/2/lock", nil, "wrong"); status != http.StatusForbidden {
		t.Fatalf("lock without grant: %d %s", status, body)
	}
	grant := adminGrant(t, admin, ts.URL, "user.manage", "2:lock", "first-password-1")
	if status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/users/2/lock", nil, grant); status != http.StatusOK || !strings.Contains(body, `"is_locked":true`) {
		t.Fatalf("lock: %d %s", status, body)
	}
	if resp, _ := get(t, bob, ts.URL+"/api/account/sessions"); resp.StatusCode == http.StatusOK {
		t.Fatal("the locked account is still signed in")
	}
	if list, _ := sys.sessions.List(t.Context(), bobAcc.ID); len(list) != 0 {
		t.Fatalf("%d sessions of the locked account", len(list))
	}

	grant = adminGrant(t, admin, ts.URL, "user.mfa_reset", "2", "first-password-1")
	if status, body := apiCall(t, admin, ts.URL, http.MethodDelete, "/admin/api/users/2/mfa", map[string]string{"confirm_username": "bob"}, grant); status != http.StatusOK {
		t.Fatalf("mfa reset: %d %s", status, body)
	}
	err = sys.db.Read(t.Context(), func(tx *store.Tx) error {
		var n int
		if err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_recovery_codes WHERE user_id = 2`).Scan(&n); err != nil || n != 0 {
			t.Errorf("recovery codes after the reset: %d %v", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	grant = adminGrant(t, admin, ts.URL, "user.manage", "2:delete", "first-password-1")
	if status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/users/2/delete", nil, grant); status != http.StatusOK || body != `{"ok":true}` {
		t.Fatalf("delete: %d %s", status, body)
	}
	err = sys.db.Read(t.Context(), func(tx *store.Tx) error {
		tables, err := accounts.OwnedTablesTx(t.Context(), tx)
		if err != nil {
			return err
		}
		for _, table := range tables {
			if table == "session_revocations" {
				continue
			}
			var n int
			if err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM "`+table+`" WHERE user_id = 2`).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("%d rows of the deleted account in %s", n, table)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sys.accounts.Get(t.Context(), 2); err == nil {
		t.Fatal("account still there")
	}
	copies, _ := filepath.Glob(filepath.Join(sys.cfg.DataDir, "go", "deleted_users", "2-*"))
	if len(copies) != 1 || accounts.VerifyRetained(copies[0], 2) != nil {
		t.Fatalf("retained copy %v", copies)
	}
	if status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/login/recovery", map[string]string{"code": "x"}, ""); status != http.StatusBadRequest ||
		!strings.Contains(body, "Complete the primary sign-in") {
		t.Fatalf("stand-alone recovery: %d %s", status, body)
	}
	// The administrator is still signed in.
	if resp, _ := get(t, admin, ts.URL+"/api/account/sessions"); resp.StatusCode != http.StatusOK {
		t.Fatalf("administrator signed out: %d", resp.StatusCode)
	}
}
