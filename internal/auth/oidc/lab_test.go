//go:build lab

// The lab tests sign in against Dex and mock-oauth2 of the shared test
// lab (tests/lab). Run them with
//
//	WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json go test -tags lab -run Lab ./internal/auth/oidc
//
// They fail, not skip, when the lab is not reachable.
package oidc

import (
	"crypto/x509"
	json "encoding/json/v2"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
)

const labRedirect = "https://localhost:5000/oidc/callback"

type labFile struct {
	RuntimeDir string `json:"runtime_dir"`
	CAFile     string `json:"ca_file"`
}

func loadLab(t *testing.T) labFile {
	t.Helper()
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test support, path set by the developer
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	var l labFile
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l labFile) secret(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(l.RuntimeDir, rel)) // #nosec G304 -- lab secret
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line)
}

func (l labFile) pool(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(l.RuntimeDir, l.CAFile)) // #nosec G304 -- lab CA
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		t.Fatal("lab CA unreadable")
	}
	return p
}

func dexProvider(t *testing.T, l labFile, change func(*Settings)) *Provider {
	t.Helper()
	s := Settings{Issuer: "https://localhost:15556/dex", ClientID: "webssh-lab", ClientSecret: l.secret(t, "secrets/dex-client-secret"),
		RedirectURI: labRedirect, RootCAs: l.pool(t), StepUpMaxAge: 5 * time.Minute, AllowedDomains: []string{"lab.test"}}
	if change != nil {
		change(&s)
	}
	return newTestProvider(t, s)
}

func mockProvider(t *testing.T, change func(*Settings)) *Provider {
	t.Helper()
	s := Settings{Issuer: "http://127.0.0.1:18080/default", ClientID: "webssh-mock", ClientSecret: "mock-secret",
		RedirectURI: labRedirect, StepUpMaxAge: 5 * time.Minute, insecureLoopback: true}
	if change != nil {
		change(&s)
	}
	return newTestProvider(t, s)
}

// userAgent follows an authorization URL like a browser, posts the login
// form once and stops at the WebSSH callback, whose query it returns.
func userAgent(t *testing.T, pool *x509.CertPool, authURL string, login url.Values) auth.Callback {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	var callback *url.URL
	client := newHTTPClient(10*time.Second, pool)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), labRedirect) {
			callback = req.URL
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if callback == nil {
		m := regexp.MustCompile(`<form method="post"(?: action="([^"]*)")?`).FindSubmatch(body)
		if m == nil {
			t.Fatalf("no login form at %s", resp.Request.URL)
		}
		action, err := resp.Request.URL.Parse(strings.ReplaceAll(string(m[1]), "&amp;", "&"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err = client.PostForm(action.String(), login)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if callback == nil {
		t.Fatalf("authorization did not reach the callback (last status %d at %s)", resp.StatusCode, resp.Request.URL)
	}
	if callback.Path != auth.PathOIDCCallback {
		t.Fatalf("callback path %q changed", callback.Path)
	}
	cb, err := auth.ParseCallback(callback.Query())
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

func dexLogin(t *testing.T, l labFile, p *Provider, f auth.Flight, user string) auth.Callback {
	t.Helper()
	u, err := p.Begin(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	return userAgent(t, l.pool(t), u, url.Values{"login": {user + "@lab.test"}, "password": {l.secret(t, "secrets/dex-"+user)}})
}

func TestLabDexSignIn(t *testing.T) {
	l := loadLab(t)
	p := dexProvider(t, l, nil)
	f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
	cb := dexLogin(t, l, p, f, "alice")
	if cb.State != f.State {
		t.Fatalf("state not echoed: %q", cb.State)
	}
	id, err := p.Complete(t.Context(), f, cb)
	if err != nil {
		t.Fatal(err)
	}
	if id.Issuer != "https://localhost:15556/dex" || id.Subject == "" || id.Email != "alice@lab.test" || !id.EmailVerified {
		t.Fatalf("identity %+v", id)
	}
	t.Logf("Dex alice: sub=%s", id.Subject)
	if _, err := p.Complete(t.Context(), f, cb); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("replayed code: %v", err)
	}
	// The same user signs in with the same subject every time.
	f2 := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
	if id2, err := p.Complete(t.Context(), f2, dexLogin(t, l, p, f2, "alice")); err != nil || id2.Subject != id.Subject {
		t.Fatalf("second sign-in: %+v %v", id2, err)
	}
}

func TestLabDexRefusals(t *testing.T) {
	l := loadLab(t)
	p := dexProvider(t, l, nil)
	t.Run("verifier of another flight", func(t *testing.T) {
		f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
		cb := dexLogin(t, l, p, f, "bob")
		f.Verifier = auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now()).Verifier
		if _, err := p.Complete(t.Context(), f, cb); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("want auth_failed, got %v", err)
		}
	})
	t.Run("nonce of another flight", func(t *testing.T) {
		f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
		cb := dexLogin(t, l, p, f, "alice")
		f.Nonce = auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now()).Nonce
		if _, err := p.Complete(t.Context(), f, cb); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("want auth_failed, got %v", err)
		}
	})
	t.Run("state of another flight", func(t *testing.T) {
		f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
		cb := dexLogin(t, l, p, f, "alice")
		other := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
		other.Verifier, other.Nonce = f.Verifier, f.Nonce
		if _, err := p.Complete(t.Context(), other, cb); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("want auth_failed, got %v", err)
		}
	})
	t.Run("audience of another client", func(t *testing.T) {
		other := dexProvider(t, l, func(s *Settings) { s.ClientID = "another-client" })
		f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
		u, err := p.Begin(t.Context(), f)
		if err != nil {
			t.Fatal(err)
		}
		cb := userAgent(t, l.pool(t), u, url.Values{"login": {"alice@lab.test"}, "password": {l.secret(t, "secrets/dex-alice")}})
		raw, _, err := p.remote.exchange(t.Context(), cb.Code, f.Verifier)
		if err != nil {
			t.Fatal(err)
		}
		_, payload, err := other.remote.verify(t.Context(), raw)
		if err != nil {
			t.Fatal(err)
		}
		m, _, _ := other.remote.metadata(t.Context())
		if _, err := parseClaims(payload, tokenCheck{Issuer: m.Issuer, ClientID: "another-client", Nonce: f.Nonce, Now: time.Now()}); err == nil {
			t.Fatal("token for webssh-lab accepted by another client")
		}
	})
	t.Run("domain allowlist", func(t *testing.T) {
		strict := dexProvider(t, l, func(s *Settings) { s.AllowedDomains = []string{"example.org"} })
		f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
		if _, err := strict.Complete(t.Context(), f, dexLogin(t, l, strict, f, "alice")); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("want auth_failed, got %v", err)
		}
	})
	t.Run("expired by the clock", func(t *testing.T) {
		late := dexProvider(t, l, func(s *Settings) { s.Now = func() time.Time { return time.Now().Add(25 * time.Hour) } })
		f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now().Add(25*time.Hour))
		if _, err := late.Complete(t.Context(), f, dexLogin(t, l, late, f, "alice")); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("want auth_failed, got %v", err)
		}
	})
}

func mockLogin(user, claims string) url.Values {
	return url.Values{"username": {user}, "claims": {claims}}
}

func mockSignIn(t *testing.T, p *Provider, purpose auth.Purpose, user, claims string) (result, error) {
	t.Helper()
	f := auth.NewFlight(auth.ProviderOIDC, purpose, time.Now())
	u, err := p.Begin(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	return p.complete(t.Context(), f, userAgent(t, nil, u, mockLogin(user, claims)))
}

// TestLabMockOAuth2Assurance signs in at mock-oauth2 with the claims the
// test chooses: acr, amr and auth_time map to assurance only as
// configured, and the step-up freshness follows auth_time.
func TestLabMockOAuth2Assurance(t *testing.T) {
	p := mockProvider(t, func(s *Settings) {
		s.Assurance = AssurancePolicy{MFAAMR: []string{"otp"}, PhishingAMR: []string{"hwk"}}
		s.StepUpACR = []string{"urn:lab:mfa"}
	})
	now := time.Now().Unix()
	res, err := mockSignIn(t, p, auth.PurposeStepUp, "alice", `{"amr":["pwd","hwk"],"acr":"urn:lab:mfa","auth_time":`+itoa(now)+`}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.identity.Assurance != auth.AssurancePhishingResistant || !p.fresh(res.assessment, true) {
		t.Fatalf("assessment %+v", res.assessment)
	}
	res, err = mockSignIn(t, p, auth.PurposeStepUp, "alice", `{"amr":["otp"],"acr":"urn:lab:mfa","auth_time":`+itoa(now-3600)+`}`)
	if err != nil || res.identity.Assurance != auth.AssuranceMFA || p.fresh(res.assessment, true) {
		t.Fatalf("old auth_time: %+v %v", res.assessment, err)
	}
	res, err = mockSignIn(t, p, auth.PurposeSignIn, "alice", `{"amr":["otp","hwk"],"auth_time":`+itoa(now)+`}`)
	if err != nil || res.identity.Assurance != auth.AssurancePhishingResistant {
		t.Fatalf("highest configured amr: %+v %v", res.assessment, err)
	}
	res, err = mockSignIn(t, p, auth.PurposeSignIn, "alice", `{"amr":["otp"]}`)
	if err != nil || res.identity.Assurance != auth.AssuranceBasic || res.assessment.Reason != "missing_auth_time" {
		t.Fatalf("no auth_time: %+v %v", res.assessment, err)
	}
	// email_verified as a string never satisfies a domain allowlist.
	strict := mockProvider(t, func(s *Settings) { s.AllowedDomains = []string{"lab.test"} })
	if _, err := mockSignIn(t, strict, auth.PurposeSignIn, "alice", `{"email":"alice@lab.test","email_verified":"true"}`); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("string email_verified admitted: %v", err)
	}
	if _, err := mockSignIn(t, strict, auth.PurposeSignIn, "alice", `{"email":"alice@lab.test","email_verified":true}`); err != nil {
		t.Fatalf("verified e-mail refused: %v", err)
	}
	// A token of mock-oauth2 does not verify against Dex's keys.
	l := loadLab(t)
	dex := dexProvider(t, l, nil)
	f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
	u, _ := p.Begin(t.Context(), f)
	cb := userAgent(t, nil, u, mockLogin("alice", "{}"))
	raw, _, err := p.remote.exchange(t.Context(), cb.Code, f.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := dex.remote.verify(t.Context(), raw); err == nil {
		t.Fatal("mock-oauth2 token verified with Dex keys")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
