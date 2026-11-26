package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth/ldap"
)

// ldapEnv is a complete LDAP configuration against an address nothing
// listens on; the files exist with the modes the secret rules require.
func ldapEnv(t *testing.T, filter string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	pw := filepath.Join(dir, "ldap_bind_password")
	ca := filepath.Join(dir, "ldap_ca.pem")
	if err := os.WriteFile(pw, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, []byte(testCAPEM(t)), 0o644); err != nil { // #nosec G306 -- a CA certificate is public
		t.Fatal(err)
	}
	return map[string]string{
		"LDAP_ENABLED": "true", "LDAP_URL": "ldap://127.0.0.1:1", "LDAP_BASE_DN": "dc=example",
		"LDAP_BIND_DN": "cn=svc,dc=example", "LDAP_BIND_PASSWORD_FILE": pw, "LDAP_CA_FILE": ca,
		"LDAP_USER_FILTER": filter, "LDAP_UNIQUE_ID_ATTRIBUTE": "entryUUID", "LDAP_PROVIDER_ID": "corp",
	}
}

// TestLDAPFilterThatDoesNotCompileDoesNotBlockStart is condition K7/A2:
// the server starts, LDAP is not ready, and its routes stay closed.
func TestLDAPFilterThatDoesNotCompileDoesNotBlockStart(t *testing.T) {
	sys, ts := openTestSystem(t, ldapEnv(t, "(&(uid={username})"))
	st, err := sys.gates.Status(t.Context(), ldap.Feature)
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready || st.Active || st.Reason == nil || !strings.Contains(*st.Reason, "LDAP runtime validation") {
		t.Fatalf("feature status %+v", st)
	}
	c := signUp(t, ts.URL, "admin1", "first-password-1")
	if resp, _ := get(t, c, ts.URL+"/admin/api/ldap/status"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status route of a not-ready LDAP: %d", resp.StatusCode)
	}
	if code := postLDAPLogin(t, ts.URL, "a", "b"); code != http.StatusNotFound {
		t.Fatalf("sign-in of a not-ready LDAP: %d", code)
	}
}

// postLDAPLogin submits the directory form of a fresh browser with its
// CSRF token and returns the status without following redirects.
func postLDAPLogin(t *testing.T, base, user, password string) int {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	_, body := get(t, c, base+"/login")
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no CSRF token on /login")
	}
	form := url.Values{"username": {user}, "password": {password}, "csrf_token": {m[1]}}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/login/ldap", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestLDAPReadyWithValidFiles: the configuration is ready at start; the
// unreachable directory shows only when it is asked.
func TestLDAPReadyWithValidFiles(t *testing.T) {
	sys, ts := openTestSystem(t, ldapEnv(t, "uid={username}"))
	st, err := sys.gates.Status(t.Context(), ldap.Feature)
	if err != nil || !st.Ready {
		t.Fatalf("feature status %+v %v", st, err)
	}
	c := signUp(t, ts.URL, "admin1", "first-password-1")
	resp, body := get(t, http.DefaultClient, ts.URL+"/login")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `id="ldapLoginForm"`) || !strings.Contains(body, ">corp<") {
		t.Fatalf("login page: %d, LDAP form missing", resp.StatusCode)
	}
	if code := postLDAPLogin(t, ts.URL, "alice", "pw"); code != http.StatusServiceUnavailable {
		t.Fatalf("sign-in with the directory down: %d", code)
	}
	resp, body = get(t, c, ts.URL+"/admin/api/ldap/status")
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, `"ready":false`) || !strings.Contains(body, `"transport":"ldap+StartTLS"`) {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
