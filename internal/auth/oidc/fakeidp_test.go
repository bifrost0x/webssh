package oidc

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	json "encoding/json/v2"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
)

// fakeIdP is a provider for the tests: discovery, a JWKS that can rotate
// and change, an authorization step the test drives and a token endpoint
// that checks client, code and PKCE verifier.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	signer    crypto.Signer
	alg, kid  string
	jwksBody  []byte
	jwksCache string
	discovery map[string]any
	codes     map[string]grant // code -> what it redeems
	// claims change the next tokens: set a key to a value, or to nil to
	// leave it out.
	claims   map[string]any
	header   string // replaces the JOSE header when set
	noIDTok  bool
	tokenErr string

	jwksHits, discoveryHits, tokenHits atomic.Int32
}

type grant struct {
	challenge, nonce string
	used             bool
}

const testClient, testSecret = "webssh-test", "client-secret"

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	testKeys(t)
	f := &fakeIdP{t: t, codes: map[string]grant{}, claims: map[string]any{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.useKey(rsaKeyA, "RS256", "a", rsaJWK(&rsaKeyA.PublicKey, "a", ""))
	f.discovery = map[string]any{
		"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
		"jwks_uri": f.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256", "ES256", "EdDSA"},
	}
	return f
}

func (f *fakeIdP) useKey(s crypto.Signer, alg, kid string, jwk ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signer, f.alg, f.kid, f.jwksBody = s, alg, kid, jwks(jwk...)
}

func (f *fakeIdP) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(f.srv.Certificate())
	return p
}

func (f *fakeIdP) settings(now func() time.Time) Settings {
	return Settings{Issuer: f.srv.URL, ClientID: testClient, ClientSecret: testSecret,
		RedirectURI: "https://webssh.example/oidc/callback", RootCAs: f.pool(), Now: now, StepUpMaxAge: 5 * time.Minute}
}

func (f *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		f.discoveryHits.Add(1)
		_ = json.MarshalWrite(w, f.discovery)
	case "/keys":
		f.jwksHits.Add(1)
		if f.jwksCache != "" {
			w.Header().Set("Cache-Control", f.jwksCache)
		}
		_, _ = w.Write(f.jwksBody)
	case "/token":
		f.tokenHits.Add(1)
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if err := r.ParseForm(); err != nil || !ok || user != testClient || pass != testSecret {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		return
	}
	g, known := f.codes[r.PostForm.Get("code")]
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if f.tokenErr != "" || !known || g.used || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge ||
		r.PostForm.Get("redirect_uri") != "https://webssh.example/oidc/callback" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	g.used = true
	f.codes[r.PostForm.Get("code")] = g
	access := "access-token-value"
	body := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300}
	if !f.noIDTok {
		body["id_token"] = f.mint(g.nonce)
	}
	_ = json.MarshalWrite(w, body)
}

// mint signs an ID Token for nonce with the current claims and key.
func (f *fakeIdP) mint(nonce string) string {
	now := time.Now()
	c := map[string]any{"iss": f.srv.URL, "sub": "subject-1", "aud": testClient, "exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(), "nonce": nonce, "email": "alice@lab.test", "email_verified": true, "preferred_username": "alice"}
	for k, v := range f.claims {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	payload, err := json.Marshal(c)
	if err != nil {
		f.t.Error(err)
	}
	hdr := `{"alg":"` + f.alg + `","kid":"` + f.kid + `"}`
	if f.header != "" {
		hdr = f.header
	}
	return sign(f.t, f.alg, f.signer, hdr, string(payload))
}

// authorize plays the user at the provider: it reads the authorization
// URL Begin returned and issues a code for its challenge and nonce.
func (f *fakeIdP) authorize(t *testing.T, authURL string) (code string, q url.Values) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q = u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != testClient || q.Get("response_type") != "code" {
		t.Fatalf("authorization request %v", q)
	}
	code = "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.codes[code] = grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	f.mu.Unlock()
	return code, q
}

func (f *fakeIdP) set(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	maps.Copy(f.claims, claims)
}

// signIn runs Begin, the provider step and complete for a fresh flight.
func signIn(t *testing.T, f *fakeIdP, p *Provider, purpose auth.Purpose) (result, error) {
	t.Helper()
	fl := auth.NewFlight(auth.ProviderOIDC, purpose, p.s.now())
	u, err := p.Begin(t.Context(), fl)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := f.authorize(t, u)
	return p.complete(t.Context(), fl, auth.Callback{Code: code, State: fl.State})
}
