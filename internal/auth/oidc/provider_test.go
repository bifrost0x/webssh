package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
)

func newTestProvider(t *testing.T, s Settings) *Provider {
	t.Helper()
	p, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSignInWithPKCEAndNonce(t *testing.T) {
	t.Parallel()
	f := newFakeIdP(t)
	p := newTestProvider(t, f.settings(nil))
	fl := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
	u, err := p.Begin(t.Context(), fl)
	if err != nil {
		t.Fatal(err)
	}
	code, q := f.authorize(t, u)
	if q.Get("state") != fl.State || q.Get("nonce") != fl.Nonce || q.Get("code_challenge") != fl.Challenge() ||
		q.Get("prompt") != "" || q.Get("scope") != "openid profile email" || q.Get("redirect_uri") != "https://webssh.example/oidc/callback" {
		t.Fatalf("authorization request %v", q)
	}
	id, err := p.Complete(t.Context(), fl, auth.Callback{Code: code, State: fl.State})
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != auth.ProviderOIDC || id.Issuer != f.srv.URL || id.Subject != "subject-1" || id.Username != "alice" ||
		!id.EmailVerified || id.Assurance != auth.AssuranceBasic {
		t.Fatalf("identity %+v", id)
	}
	// The code is spent: the provider refuses it again.
	if _, err := p.Complete(t.Context(), fl, auth.Callback{Code: code, State: fl.State}); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("replayed code: %v", err)
	}
	if n := f.discoveryHits.Load(); n != 1 {
		t.Fatalf("discovery fetched %d times", n)
	}
}

func TestBeginAsksForReauthentication(t *testing.T) {
	t.Parallel()
	f := newFakeIdP(t)
	s := f.settings(nil)
	s.StepUpACR = []string{"urn:b", "urn:a", "urn:b"}
	p := newTestProvider(t, s)
	for purpose, want := range map[auth.Purpose]url.Values{
		auth.PurposeLink:   {"prompt": {"login"}},
		auth.PurposeStepUp: {"prompt": {"login"}, "max_age": {"0"}, "acr_values": {"urn:a urn:b"}},
	} {
		u, err := p.Begin(t.Context(), auth.NewFlight(auth.ProviderOIDC, purpose, time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		_, q := f.authorize(t, u)
		for k, v := range want {
			if q.Get(k) != v[0] {
				t.Fatalf("%s: %s=%q", purpose, k, q.Get(k))
			}
		}
	}
	u, err := p.begin(t.Context(), auth.NewFlight(auth.ProviderOIDC, auth.PurposeStepUp, time.Now()), false)
	if err != nil || strings.Contains(u, "acr_values") {
		t.Fatalf("account step-up without MFA asks for acr: %s %v", u, err)
	}
	if _, err := p.Begin(t.Context(), auth.NewFlight(auth.ProviderGitHub, auth.PurposeSignIn, time.Now())); err == nil {
		t.Fatal("a GitHub flight was begun")
	}
}

// TestIDTokenNegativeVectors are the refusals of the M2 plan's DoD: wrong
// alg, none, foreign kid, expired, wrong aud and azp, a nonce of another
// flight, plus the claim checks around them.
func TestIDTokenNegativeVectors(t *testing.T) {
	t.Parallel()
	testKeys(t)
	now := time.Now().Unix()
	cases := map[string]func(f *fakeIdP){
		"alg none": func(f *fakeIdP) { f.header = `{"alg":"none"}` },
		"alg HS256": func(f *fakeIdP) {
			f.header = `{"alg":"HS256","kid":"a"}`
		},
		"alg not announced": func(f *fakeIdP) {
			f.signer, f.alg, f.kid = rsaKeyA, "PS256", "a"
		},
		"foreign kid":         func(f *fakeIdP) { f.kid = "unknown" },
		"key of another kid":  func(f *fakeIdP) { f.signer = rsaKeyB },
		"expired":             func(f *fakeIdP) { f.claims["exp"] = now - 121 },
		"exp missing":         func(f *fakeIdP) { f.claims["exp"] = nil },
		"exp as string":       func(f *fakeIdP) { f.claims["exp"] = "4102444800" },
		"issued in future":    func(f *fakeIdP) { f.claims["iat"] = now + 600 },
		"not yet valid":       func(f *fakeIdP) { f.claims["nbf"] = now + 600 },
		"wrong aud":           func(f *fakeIdP) { f.claims["aud"] = "other-client" },
		"aud list without us": func(f *fakeIdP) { f.claims["aud"] = []string{"a", "b"} },
		"several aud no azp":  func(f *fakeIdP) { f.claims["aud"] = []string{testClient, "other"} },
		"wrong azp":           func(f *fakeIdP) { f.claims["azp"] = "other" },
		"azp not a string":    func(f *fakeIdP) { f.claims["azp"] = 7 },
		"wrong issuer":        func(f *fakeIdP) { f.claims["iss"] = "https://evil.example" },
		"no subject":          func(f *fakeIdP) { f.claims["sub"] = nil },
		"numeric subject":     func(f *fakeIdP) { f.claims["sub"] = 42 },
		"long subject":        func(f *fakeIdP) { f.claims["sub"] = strings.Repeat("s", 513) },
		"nonce of another":    func(f *fakeIdP) { f.claims["nonce"] = "nonce-of-another-flight" },
		"nonce missing":       func(f *fakeIdP) { f.claims["nonce"] = nil },
		"at_hash mismatch":    func(f *fakeIdP) { f.claims["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" },
		"no id_token":         func(f *fakeIdP) { f.noIDTok = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFakeIdP(t)
			f.mu.Lock()
			change(f)
			f.mu.Unlock()
			p := newTestProvider(t, f.settings(nil))
			if _, err := signIn(t, f, p, auth.PurposeSignIn); !fault.Is(err, fault.AuthFailed) {
				t.Fatalf("want auth_failed, got %v", err)
			}
		})
	}
	t.Run("several aud with our azp", func(t *testing.T) {
		t.Parallel()
		f := newFakeIdP(t)
		f.set(map[string]any{"aud": []string{testClient, "other"}, "azp": testClient})
		if _, err := signIn(t, f, newTestProvider(t, f.settings(nil)), auth.PurposeSignIn); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("matching at_hash", func(t *testing.T) {
		t.Parallel()
		f := newFakeIdP(t)
		sum := sha256.Sum256([]byte("access-token-value"))
		f.set(map[string]any{"at_hash": base64.RawURLEncoding.EncodeToString(sum[:16])})
		if _, err := signIn(t, f, newTestProvider(t, f.settings(nil)), auth.PurposeSignIn); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFlightChecks(t *testing.T) {
	t.Parallel()
	f := newFakeIdP(t)
	p := newTestProvider(t, f.settings(nil))
	fl := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
	u, err := p.Begin(t.Context(), fl)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := f.authorize(t, u)
	other := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())
	for name, cb := range map[string]auth.Callback{
		"state of another flight": {Code: code, State: other.State},
		"provider error":          {Code: code, State: fl.State, Error: "access_denied"},
		"no code":                 {State: fl.State},
	} {
		if _, err := p.Complete(t.Context(), fl, cb); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// The verifier of another flight does not redeem the code (PKCE).
	stolen := fl
	stolen.Verifier = other.Verifier
	if _, err := p.Complete(t.Context(), stolen, auth.Callback{Code: code, State: fl.State}); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("foreign verifier: %v", err)
	}
	expired := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now().Add(-auth.FlightTTL-time.Second))
	if _, err := p.Complete(t.Context(), expired, auth.Callback{Code: code, State: expired.State}); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("expired flight: %v", err)
	}
	if n := f.tokenHits.Load(); n != 1 {
		t.Fatalf("token endpoint asked %d times; refused flights must not reach it", n)
	}
}

func TestAllowlists(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		subjects []string
		domains  []string
		claims   map[string]any
		ok       bool
	}{
		{"subject listed", []string{"subject-1"}, nil, nil, true},
		{"subject not listed", []string{"other"}, nil, nil, false},
		{"domain listed", nil, []string{"lab.test"}, nil, true},
		{"domain upper case", nil, []string{"lab.test"}, map[string]any{"email": "Alice@LAB.Test"}, true},
		{"domain not listed", nil, []string{"example.org"}, nil, false},
		{"email not verified", nil, []string{"lab.test"}, map[string]any{"email_verified": false}, false},
		{"email_verified as string", nil, []string{"lab.test"}, map[string]any{"email_verified": "true"}, false},
		{"no email", nil, []string{"lab.test"}, map[string]any{"email": nil}, false},
		{"subdomain is another domain", nil, []string{"lab.test"}, map[string]any{"email": "a@x.lab.test"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeIdP(t)
			f.set(c.claims)
			s := f.settings(nil)
			s.AllowedSubjects, s.AllowedDomains = c.subjects, c.domains
			_, err := signIn(t, f, newTestProvider(t, s), auth.PurposeSignIn)
			if c.ok != (err == nil) || err != nil && !fault.Is(err, fault.AuthFailed) {
				t.Fatalf("ok=%v err=%v", c.ok, err)
			}
		})
	}
}

func TestAssuranceAndStepUpFreshness(t *testing.T) {
	t.Parallel()
	f := newFakeIdP(t)
	s := f.settings(nil)
	s.Assurance = AssurancePolicy{MFAAMR: []string{"otp"}, PhishingAMR: []string{"hwk"}}
	s.StepUpACR = []string{"urn:mfa"}
	p := newTestProvider(t, s)
	now := time.Now().Unix()
	f.set(map[string]any{"amr": []string{"pwd", "otp"}, "auth_time": now - 10, "acr": "urn:mfa"})
	res, err := signIn(t, f, p, auth.PurposeStepUp)
	if err != nil {
		t.Fatal(err)
	}
	if res.identity.Assurance != auth.AssuranceMFA || !p.fresh(res.assessment, true) {
		t.Fatalf("assessment %+v", res.assessment)
	}
	f.set(map[string]any{"auth_time": now - 301})
	if res, _ = signIn(t, f, p, auth.PurposeStepUp); p.fresh(res.assessment, true) {
		t.Fatal("an old authentication counts as fresh")
	}
	f.set(map[string]any{"auth_time": now - 5, "acr": "urn:other"})
	if res, _ = signIn(t, f, p, auth.PurposeStepUp); p.fresh(res.assessment, true) || !p.fresh(res.assessment, false) {
		t.Fatal("acr requirement not applied as asked")
	}
	f.set(map[string]any{"auth_time": nil})
	if res, _ = signIn(t, f, p, auth.PurposeStepUp); res.identity.Assurance != auth.AssuranceBasic || p.fresh(res.assessment, false) {
		t.Fatalf("missing auth_time: %+v", res.assessment)
	}
}

// TestJWKSRotationAndExpiry is the K7 condition on the key cache: keys
// expire after their lifetime and are fetched again, a rotated key is
// fetched once on an unknown kid, and a stream of unknown kids does not
// make WebSSH fetch more than every minJWKSRefresh.
func TestJWKSRotationAndExpiry(t *testing.T) {
	t.Parallel()
	testKeys(t)
	f := newFakeIdP(t)
	f.jwksCache = "public, max-age=120"
	clock := time.Now()
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); defer mu.Unlock(); clock = clock.Add(d) }
	p := newTestProvider(t, f.settings(now))
	if _, err := signIn(t, f, p, auth.PurposeSignIn); err != nil {
		t.Fatal(err)
	}
	if f.jwksHits.Load() != 1 {
		t.Fatalf("jwks hits %d", f.jwksHits.Load())
	}
	// Within max-age the cache answers.
	advance(60 * time.Second)
	if _, err := signIn(t, f, p, auth.PurposeSignIn); err != nil || f.jwksHits.Load() != 1 {
		t.Fatalf("cached keys not used: %v, hits %d", err, f.jwksHits.Load())
	}
	// After max-age the keys are fetched again.
	advance(61 * time.Second)
	if _, err := signIn(t, f, p, auth.PurposeSignIn); err != nil || f.jwksHits.Load() != 2 {
		t.Fatalf("expired keys not renewed: %v, hits %d", err, f.jwksHits.Load())
	}
	// Rotation: the provider signs with a new kid; one fetch finds it.
	f.useKey(ecKeys["P-256"], "ES256", "b", rsaJWK(&rsaKeyA.PublicKey, "a", ""), ecJWK(ecKeys["P-256"], "b", "P-256"))
	advance(minJWKSRefresh)
	if _, err := signIn(t, f, p, auth.PurposeSignIn); err != nil || f.jwksHits.Load() != 3 {
		t.Fatalf("rotated key: %v, hits %d", err, f.jwksHits.Load())
	}
	// Unknown kids right after a fetch do not reach the provider.
	f.mu.Lock()
	f.kid = "c"
	f.mu.Unlock()
	for range 3 {
		if _, err := signIn(t, f, p, auth.PurposeSignIn); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("unknown kid: %v", err)
		}
	}
	if f.jwksHits.Load() != 3 {
		t.Fatalf("unknown kids fetched the keys: %d", f.jwksHits.Load())
	}
	// Expired keys are never used when the provider is down.
	advance(maxJWKSAge)
	f.mu.Lock()
	f.kid = "b"
	f.jwksBody = []byte("not json")
	f.mu.Unlock()
	if _, err := signIn(t, f, p, auth.PurposeSignIn); !fault.Is(err, fault.Unavailable) {
		t.Fatalf("expired keys with a broken provider: %v", err)
	}
}

// TestRedirectWithResolvableTarget is the K7 condition: a provider answer
// that redirects to a host that resolves and answers is not followed.
func TestRedirectWithResolvableTarget(t *testing.T) {
	t.Parallel()
	f := newFakeIdP(t)
	var reached bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"x"}`))
	}))
	t.Cleanup(target.Close)
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	s := f.settings(nil)
	s.Issuer = redirector.URL
	s.RootCAs.AddCert(target.Certificate())
	s.RootCAs.AddCert(redirector.Certificate())
	p := newTestProvider(t, s)
	_, err := p.Begin(t.Context(), auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now()))
	if !fault.Is(err, fault.Unavailable) || reached {
		t.Fatalf("redirect followed (reached=%v): %v", reached, err)
	}
}

func TestDiscoveryChecks(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(m map[string]any){
		"foreign issuer":        func(m map[string]any) { m["issuer"] = "https://evil.example" },
		"http token endpoint":   func(m map[string]any) { m["token_endpoint"] = "http://idp.example/token" },
		"jwks with user info":   func(m map[string]any) { m["jwks_uri"] = "https://u:p@idp.example/keys" },
		"only symmetric algs":   func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"HS256"} },
		"no token endpoint":     func(m map[string]any) { delete(m, "token_endpoint") },
		"issuer of wrong type":  func(m map[string]any) { m["issuer"] = 7 },
		"authorization in http": func(m map[string]any) { m["authorization_endpoint"] = "http://idp.example/a" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFakeIdP(t)
			f.mu.Lock()
			change(f.discovery)
			f.mu.Unlock()
			p := newTestProvider(t, f.settings(nil))
			if _, err := p.Begin(t.Context(), auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())); !fault.Is(err, fault.Unavailable) {
				t.Fatalf("want unavailable, got %v", err)
			}
		})
	}
	t.Run("trailing slash of the issuer", func(t *testing.T) {
		t.Parallel()
		f := newFakeIdP(t)
		f.discovery["issuer"] = f.srv.URL + "/"
		f.set(map[string]any{"iss": f.srv.URL + "/"})
		res, err := signIn(t, f, newTestProvider(t, f.settings(nil)), auth.PurposeSignIn)
		if err != nil || res.identity.Issuer != f.srv.URL {
			t.Fatalf("issuer %q: %v", res.identity.Issuer, err)
		}
	})
	t.Run("provider down is unavailable, not a crash at start", func(t *testing.T) {
		t.Parallel()
		f := newFakeIdP(t)
		s := f.settings(nil)
		f.srv.Close()
		p := newTestProvider(t, s)
		if _, err := p.Begin(t.Context(), auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, time.Now())); !fault.Is(err, fault.Unavailable) {
			t.Fatalf("want unavailable, got %v", err)
		}
	})
}

func TestSettingsValidation(t *testing.T) {
	t.Parallel()
	good := Settings{Issuer: "https://idp.example", ClientID: "c", ClientSecret: "s", RedirectURI: "https://w.example/oidc/callback"}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(s *Settings){
		"http issuer":       func(s *Settings) { s.Issuer = "http://idp.example" },
		"slash issuer":      func(s *Settings) { s.Issuer = "https://idp.example/" },
		"no secret":         func(s *Settings) { s.ClientSecret = "" },
		"other callback":    func(s *Settings) { s.RedirectURI = "https://w.example/callback" },
		"callback query":    func(s *Settings) { s.RedirectURI = "https://w.example/oidc/callback?x=1" },
		"loopback http lab": func(s *Settings) { s.Issuer = "http://127.0.0.1:18080/default" },
	} {
		s := good
		change(&s)
		if _, err := New(s); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func FuzzParseClaims(f *testing.F) {
	f.Add([]byte(`{"iss":"https://i","sub":"s","aud":["c","d"],"azp":"c","exp":1e12,"iat":1,"nonce":"n"}`))
	f.Add([]byte(`{"iss":"https://i","sub":"s","aud":"c","exp":"1","iat":1,"nonce":"n"}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		c, err := parseClaims(payload, tokenCheck{Issuer: "https://i", ClientID: "c", Nonce: "n", Now: time.Unix(1000, 0)})
		if err != nil {
			return
		}
		if c.Subject == "" {
			t.Fatal("accepted claims without subject")
		}
	})
}
