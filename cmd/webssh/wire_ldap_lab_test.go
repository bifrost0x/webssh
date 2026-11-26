//go:build lab

package main

import (
	json "encoding/json/v2"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// labLDAPEnv points LDAP at ldap1 of the test lab (WEBSSH_LAB_JSON).
func labLDAPEnv(t *testing.T) (map[string]string, func(name string) string) {
	t.Helper()
	inv := os.Getenv("WEBSSH_LAB_JSON")
	if inv == "" {
		t.Fatal("set WEBSSH_LAB_JSON to the lab inventory")
	}
	root := filepath.Dir(inv)
	secret := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(root, "secrets", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimRight(strings.SplitN(string(raw), "\n", 2)[0], "\r")
	}
	pw := filepath.Join(t.TempDir(), "ldap_bind_password")
	if err := os.WriteFile(pw, []byte(secret("ldap-bind-webssh")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"LDAP_ENABLED": "true", "LDAP_AUTO_PROVISION": "true", "LDAP_URL": "ldap://127.0.0.1:13389",
		"LDAP_BASE_DN": "dc=lab,dc=test", "LDAP_BIND_DN": "cn=webssh,ou=services,dc=lab,dc=test",
		"LDAP_BIND_PASSWORD_FILE": pw, "LDAP_CA_FILE": filepath.Join(root, "ca", "ca.crt"),
		"LDAP_USER_FILTER": "(&(objectClass=inetOrgPerson)(uid={username}))", "LDAP_UNIQUE_ID_ATTRIBUTE": "entryUUID",
		"LDAP_PROVIDER_ID": "lab",
	}, secret
}

var csrfMeta = regexp.MustCompile(`name="csrf-token" content="([^"]+)"`)

// TestLabLDAPSignInOverHTTP signs a directory user in through the real
// sign-in form, provisions the account, and proves the directory
// password again for a step-up.
func TestLabLDAPSignInOverHTTP(t *testing.T) {
	env, secret := labLDAPEnv(t)
	_, ts := openTestSystem(t, env)
	admin := signUp(t, ts.URL, "admin1", "first-password-1")
	if resp, body := get(t, admin, ts.URL+"/admin/api/ldap/status"); resp.StatusCode != 200 || !strings.Contains(body, `"ready":true`) {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	if code := postLDAPLogin(t, ts.URL, "alice", "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	_, body := get(t, c, ts.URL+"/login")
	m := csrfField.FindStringSubmatch(body)
	form := url.Values{"username": {" alice "}, "password": {secret("ldap-alice")}, "csrf_token": {m[1]}}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+"/login/ldap", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("sign-in: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body = get(t, c, ts.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("workspace: %d", resp.StatusCode)
	}
	token := csrfMeta.FindStringSubmatch(body)
	if token == nil {
		t.Fatal("no CSRF meta tag on the workspace")
	}
	post := func(path, payload string) (int, map[string]any) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+path, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRFToken", token[1])
		req.Header.Set("Origin", ts.URL)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}
	code, intent := post("/api/account/step-up/intents", `{"action":"key.upload"}`)
	if code != 200 || intent["preferred_method"] != "ldap" {
		t.Fatalf("intent: %d %v", code, intent)
	}
	if code, out := post("/api/account/step-up/ldap", `{"intent":"`+intent["intent"].(string)+`","password":"wrong"}`); code != 403 {
		t.Fatalf("wrong directory password: %d %v", code, out)
	}
	code, grant := post("/api/account/step-up/ldap", `{"intent":"`+intent["intent"].(string)+`","password":"`+secret("ldap-alice")+`"}`)
	if code != 200 || grant["grant"] == nil || grant["method"] != "ldap" {
		t.Fatalf("step-up: %d %v", code, grant)
	}
	// The administrator sees the provisioned identity.
	resp, body = get(t, admin, ts.URL+"/admin/api/users")
	if resp.StatusCode != 200 || !strings.Contains(body, `"username":"alice"`) || !strings.Contains(body, `"ldap_managed":true`) {
		t.Fatalf("users: %d %s", resp.StatusCode, body)
	}
}
