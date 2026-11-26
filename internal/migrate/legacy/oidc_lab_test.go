//go:build lab

package legacy

import (
	"crypto/tls"
	"crypto/x509"
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
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/oidc"
)

const dexIssuer, dexRedirect = "https://localhost:15556/dex", "https://localhost:5000/oidc/callback"

type oidcLab struct {
	RuntimeDir string `json:"runtime_dir"`
	CAFile     string `json:"ca_file"`
}

func loadOIDCLab(t *testing.T) (oidcLab, *x509.CertPool) {
	t.Helper()
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test support
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	var l oidcLab
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(filepath.Join(l.RuntimeDir, l.CAFile)) // #nosec G304 -- lab CA
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("lab CA unreadable")
	}
	return l, pool
}

func (l oidcLab) secret(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(l.RuntimeDir, rel)) // #nosec G304 -- lab secret
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line)
}

// dexSignIn signs alice in at Dex like a browser and returns the identity
// the provider vouches for.
func dexSignIn(t *testing.T, l oidcLab, pool *x509.CertPool, p *oidc.Provider) auth.Identity {
	t.Helper()
	f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
	authURL, err := p.Begin(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	var callback *url.URL
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), dexRedirect) {
				callback = req.URL
				return http.ErrUseLastResponse
			}
			return nil
		}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := regexp.MustCompile(`<form method="post"(?: action="([^"]*)")?`).FindSubmatch(body)
	if m == nil {
		t.Fatalf("no login form at %s", resp.Request.URL)
	}
	action, err := resp.Request.URL.Parse(strings.ReplaceAll(string(m[1]), "&amp;", "&"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.PostForm(action.String(), url.Values{"login": {"alice@lab.test"}, "password": {l.secret(t, "secrets/dex-alice")}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if callback == nil {
		t.Fatal("Dex did not redirect to the callback")
	}
	cb, err := auth.ParseCallback(callback.Query())
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.Complete(t.Context(), f, cb)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestLabOIDCIdentityAfterMigration is the functional verification of
// E05: an identity Python stored for Dex signs in after the migration and
// reaches the same account.
func TestLabOIDCIdentityAfterMigration(t *testing.T) {
	l, pool := loadOIDCLab(t)
	p, err := oidc.New(oidc.Settings{Issuer: dexIssuer, ClientID: "webssh-lab", ClientSecret: l.secret(t, "secrets/dex-client-secret"),
		RedirectURI: dexRedirect, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	subject := dexSignIn(t, l, pool, p).Subject

	dir := copyGolden(t)
	// The Python release stored the issuer without a trailing slash and
	// the subject as Dex sent it; account 8 is oidc_user of the data set.
	execLegacySQL(t, dir, `INSERT INTO oidc_identities (id, user_id, issuer, subject, created_at)
		VALUES (2, 8, '`+dexIssuer+`', '`+subject+`', '2026-11-03 10:00:00.000001')`)
	before := legacySnapshot(t, dir)
	st, err := startClosed(oidcOptions(t, dir, nil))
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dir, before)
	m := openMigrated(t, dir, golden.manifest.SecretKey.Value, st.Report)
	links := &oidc.Links{DB: m.db}
	id := dexSignIn(t, l, pool, p)
	userID, err := links.Account(t.Context(), id)
	if err != nil || userID != 8 {
		t.Fatalf("Dex sign-in after the migration reaches %d: %v", userID, err)
	}
	t.Logf("Dex sub %s resolves to account %d after the migration", id.Subject, userID)
}
