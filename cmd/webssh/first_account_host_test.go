package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

// registerThrough loads /register and posts the form with Host set to
// host, as a page served under that name would (DNS rebinding).
func registerThrough(t *testing.T, base, host, user string) (int, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	get, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/register", nil)
	get.Host = host
	resp, err := c.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfField.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no CSRF token on /register through %s (%d)", host, resp.StatusCode)
	}
	form := url.Values{"username": {user}, "password": {"password-123"}, "confirm_password": {"password-123"}, "csrf_token": {string(m[1])}}
	post, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/register", strings.NewReader(form.Encode()))
	post.Host = host
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "http://"+host)
	resp, err = c.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(page) + string(body)
}

// The bootstrap registration of a fresh installation is refused through a
// DNS name that is not in ALLOWED_HOSTS (finding #68: a rebound name
// would otherwise create the administrator from a visitor's browser). An
// IP address keeps working, and so does a name of ALLOWED_HOSTS.
func TestFirstAccountRefusedThroughAnUnlistedName(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{"RATELIMIT_ENABLED": "false"})
	_, port, _ := strings.Cut(strings.TrimPrefix(ts.URL, "http://"), ":")
	status, body := registerThrough(t, ts.URL, "rebind.attacker.test:"+port, "rebind")
	if status != http.StatusForbidden || !strings.Contains(body, "ALLOWED_HOSTS") {
		t.Fatalf("registration through a rebound name: %d", status)
	}
	if has, err := sys.accounts.HasAccounts(t.Context()); err != nil || has {
		t.Fatalf("an account exists after the refusal: %v %v", has, err)
	}
	if status, _ := registerThrough(t, ts.URL, "127.0.0.1:"+port, "admin1"); status != http.StatusFound {
		t.Fatalf("registration through the IP address: %d", status)
	}

	sys2, ts2 := openTestSystem(t, map[string]string{"RATELIMIT_ENABLED": "false", "ALLOWED_HOSTS": "ssh.example.test"})
	_, port2, _ := strings.Cut(strings.TrimPrefix(ts2.URL, "http://"), ":")
	if status, _ := registerThrough(t, ts2.URL, "ssh.example.test:"+port2, "admin1"); status != http.StatusFound {
		t.Fatalf("registration through a name of ALLOWED_HOSTS: %d", status)
	}
	if has, _ := sys2.accounts.HasAccounts(t.Context()); !has {
		t.Fatal("no account through a name of ALLOWED_HOSTS")
	}
}
