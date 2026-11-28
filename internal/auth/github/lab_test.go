//go:build lab

// The lab tests sign in against the GitHub stub of the shared test lab
// (tests/lab/github-stub): authorize with PKCE, token exchange, profile and
// organization membership over TLS with the lab's certificate authority.
// Run them with
//
//	WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json go test -tags lab -run Lab ./internal/auth/github
//
// They fail, not skip, when the lab is not reachable.
package github

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
)

type labInventory struct {
	RuntimeDir string `json:"runtime_dir"`
	CAFile     string `json:"ca_file"`
	Services   map[string]struct {
		BaseURL string `json:"base_url"`
		Client  struct {
			ID         string `json:"id"`
			SecretFile string `json:"secret_file"`
		} `json:"client"`
	} `json:"services"`
}

// LabStub is the GitHub stub of the lab: its base URL, a client that
// trusts the lab CA and the stub's client credentials.
type labStub struct {
	base, clientID, secret string
	http                   *http.Client
}

func loadLabStub(t *testing.T) labStub {
	t.Helper()
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test input set by the developer
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	var inv labInventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	svc := inv.Services["github-stub"]
	pem, err := os.ReadFile(filepath.Join(inv.RuntimeDir, inv.CAFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	secret, err := os.ReadFile(filepath.Join(inv.RuntimeDir, svc.Client.SecretFile))
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(secret), "\n")
	return labStub{base: svc.BaseURL, clientID: svc.Client.ID, secret: strings.TrimRight(line, "\r"),
		http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}
}

// labEnv is the unit-test environment with the stub in place of the fake.
func labEnv(t *testing.T, extra map[string]any) (*env, labStub) {
	t.Helper()
	stub := loadLabStub(t)
	e := newEnv(t)
	e.svc.Client = Client{WebURL: stub.base, APIURL: stub.base, HTTP: stub.http}
	body := map[string]any{"enabled": true, "client_id": stub.clientID, "client_secret": stub.secret, "redirect_uri": testRedirect}
	maps.Copy(body, extra)
	raw, _ := json.Marshal(body)
	if _, err := e.svc.Update(t.Context(), raw, 1); err != nil {
		t.Fatalf("configure: %v", err)
	}
	return e, stub
}

// stubAuthorize follows the authorization URL of start at the stub, which
// signs in login and redirects to the callback; it returns that callback
// path with its query.
func stubAuthorize(t *testing.T, stub labStub, start string, login string) string {
	t.Helper()
	client := *stub.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(start + "&login=" + url.QueryEscape(login))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || loc.Path != "/auth/github/callback" {
		t.Fatalf("authorize: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	return loc.Path + "?" + loc.RawQuery
}

func labLogin(t *testing.T, e *env, stub labStub, login string) (int, string) {
	t.Helper()
	start := e.do("GET", "/auth/github/login", "lab", none, nil, "")
	if start.Code != http.StatusFound {
		t.Fatalf("login: %d %s", start.Code, start.Body)
	}
	rec := e.do("GET", stubAuthorize(t, stub, start.Header().Get("Location"), login), "lab", none, nil, "")
	return rec.Code, rec.Body.String()
}

func TestLabGitHubSignIn(t *testing.T) {
	e, stub := labEnv(t, nil)
	alice := e.accounts.add("alice", "")
	e.link(alice, "1001", false)
	if code, body := labLogin(t, e, stub, "octo-alice"); code != http.StatusFound || e.signIn.signed[0] != alice {
		t.Fatalf("linked: %d %s", code, body)
	}
	if code, body := labLogin(t, e, stub, "octo-carol"); code != http.StatusForbidden || !strings.Contains(body, msgNotLinked) {
		t.Fatalf("unlinked: %d %s", code, body)
	}
}

func TestLabGitHubOrganizationPolicy(t *testing.T) {
	cases := []struct {
		orgs   string
		login  string
		status int
	}{
		{"lab-org", "octo-alice", http.StatusFound},
		{"lab-org", "octo-bob", http.StatusForbidden},
		{"lab-org", "octo-carol", http.StatusForbidden},
		{"flaky-org", "octo-alice", http.StatusServiceUnavailable},
		{"flaky-org,lab-org", "octo-alice", http.StatusFound},
		{"flaky-org,lab-org", "octo-bob", http.StatusServiceUnavailable},
		{"other-org,lab-org", "octo-carol", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.orgs+"/"+tc.login, func(t *testing.T) {
			e, stub := labEnv(t, map[string]any{"allowed_orgs": tc.orgs, "auto_provision": true})
			if code, body := labLogin(t, e, stub, tc.login); code != tc.status {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
}

func TestLabGitHubProvisionAndLink(t *testing.T) {
	e, stub := labEnv(t, map[string]any{"auto_provision": true, "allowed_orgs": "lab-org"})
	if code, body := labLogin(t, e, stub, "octo-alice"); code != http.StatusFound {
		t.Fatalf("provision: %d %s", code, body)
	}
	id, err := e.svc.Account(t.Context(), identityFor("1001"))
	if err != nil || e.accounts.get(id).Username != "octo_alice" || e.accounts.get(id).Managed != "github" {
		t.Fatalf("provisioned %d %+v %v", id, e.accounts.get(id), err)
	}
	// Linking applies the organization policy too: octo-carol is no
	// member of lab-org, and links once the policy is lifted.
	carol := e.accounts.add("carol", "")
	p := principal.Principal{UserID: carol, SessionID: "lab-s", Username: "carol"}
	link := func() (int, string) {
		start := e.do("POST", "/api/account/github/link/start", "lab", p, grant(principal.ActionGitHubLink, itoa(carol)), "{}")
		var body map[string]string
		if err := json.Unmarshal(start.Body.Bytes(), &body); err != nil {
			t.Fatalf("link start: %d %s", start.Code, start.Body)
		}
		rec := e.do("GET", stubAuthorize(t, stub, body["authorization_url"], "octo-carol"), "lab", p, nil, "")
		return rec.Code, rec.Body.String()
	}
	if code, body := link(); code != http.StatusForbidden || !strings.Contains(body, msgOrgRequired) {
		t.Fatalf("link outside the organization: %d %s", code, body)
	}
	if _, err := e.svc.Update(t.Context(), []byte(`{"allowed_orgs": [], "auto_provision": false}`), 1); err != nil {
		t.Fatal(err)
	}
	if code, body := link(); code != http.StatusFound {
		t.Fatalf("link: %d %s", code, body)
	}
	if id, err := e.svc.Account(t.Context(), identityFor("1003")); err != nil || id != carol {
		t.Fatalf("linked to %d, %v", id, err)
	}
}

func TestLabGitHubWrongSecretIsUnavailable(t *testing.T) {
	stub := loadLabStub(t)
	e := newEnv(t)
	e.svc.Client = Client{WebURL: stub.base, APIURL: stub.base, HTTP: stub.http}
	raw, _ := json.Marshal(map[string]any{"enabled": true, "client_id": stub.clientID, "client_secret": "not-the-lab-secret-xxxxxxxx", "redirect_uri": testRedirect})
	if _, err := e.svc.Update(t.Context(), raw, 1); err != nil {
		t.Fatal(err)
	}
	if code, body := labLogin(t, e, stub, "octo-alice"); code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", code, body)
	}
}
