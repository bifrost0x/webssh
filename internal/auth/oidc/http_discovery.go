package oidc

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Lifetimes of the provider data. Discovery is fetched on first use, not
// at start (a provider that is down must not stop WebSSH, as with Authlib's
// lazy metadata), and again after metadataMaxAge. Keys are fetched again
// after their lifetime, which a Cache-Control max-age sets within
// [minJWKSAge, maxJWKSAge]; a token whose kid is unknown fetches them at
// most every minJWKSRefresh.
const (
	metadataMaxAge = 24 * time.Hour
	minJWKSAge     = time.Minute
	maxJWKSAge     = 24 * time.Hour
	minJWKSRefresh = 30 * time.Second
)

// metadata is the part of the discovery document WebSSH uses (OIDC
// Discovery 1.0 section 3).
type metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// remote holds the provider data. One fetch runs at a time; readers
// never wait for the network while the cache is fresh.
type remote struct {
	s      Settings
	client *http.Client

	fetch sync.Mutex // serializes network fetches

	mu        sync.Mutex
	meta      metadata
	allowed   map[string]bool
	metaAt    time.Time
	keys      []jwk
	keysAt    time.Time // when the keys were fetched
	keysUntil time.Time // when they must be fetched again
}

func newRemote(s Settings) *remote {
	return &remote{s: s, client: newHTTPClient(s.timeout(), s.RootCAs)}
}

// metadata returns the discovery document, fetching it when it is
// missing or old. A failed refresh keeps a document fetched before.
func (r *remote) metadata(ctx context.Context) (metadata, map[string]bool, error) {
	if m, a, ok := r.cachedMeta(); ok {
		return m, a, nil
	}
	r.fetch.Lock()
	defer r.fetch.Unlock()
	if m, a, ok := r.cachedMeta(); ok {
		return m, a, nil
	}
	m, allowed, err := r.discover(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		if !r.metaAt.IsZero() {
			return r.meta, r.allowed, nil
		}
		return metadata{}, nil, err
	}
	r.meta, r.allowed, r.metaAt = m, allowed, r.s.now()
	return m, allowed, nil
}

func (r *remote) cachedMeta() (metadata, map[string]bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.metaAt.IsZero() || r.s.now().Sub(r.metaAt) >= metadataMaxAge {
		return metadata{}, nil, false
	}
	return r.meta, r.allowed, true
}

// discover loads the discovery document (OIDC Discovery 1.0 section 4).
// Its issuer must be the configured one (a trailing slash aside, which
// the Python release also stripped), and every endpoint must be https.
func (r *remote) discover(ctx context.Context) (metadata, map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.s.timeout())
	defer cancel()
	body, _, err := getJSON(ctx, r.client, r.s.Issuer+"/.well-known/openid-configuration")
	if err != nil {
		return metadata{}, nil, err
	}
	var m metadata
	if err := json.Unmarshal(body, &m); err != nil {
		return metadata{}, nil, fmt.Errorf("%w: discovery document: %w", errProvider, err)
	}
	if strings.TrimRight(m.Issuer, "/") != r.s.Issuer {
		return metadata{}, nil, fmt.Errorf("%w: discovery issuer %q is not the configured issuer", errProvider, m.Issuer)
	}
	for _, endpoint := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.JWKSURI} {
		if err := r.s.checkEndpoint(endpoint); err != nil {
			return metadata{}, nil, fmt.Errorf("%w: discovery endpoint: %w", errProvider, err)
		}
	}
	algs := m.SigningAlgs
	if len(algs) == 0 {
		algs = []string{"RS256"} // the default of OIDC Discovery 1.0
	}
	allowed := map[string]bool{}
	for _, a := range algs {
		if _, ok := algorithms[a]; ok {
			allowed[a] = true
		}
	}
	if len(allowed) == 0 {
		return metadata{}, nil, fmt.Errorf("%w: the provider offers no supported signing algorithm", errProvider)
	}
	return m, allowed, nil
}

// currentKeys returns the cached keys while they are fresh.
func (r *remote) currentKeys() ([]jwk, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keys, r.keys != nil && r.s.now().Before(r.keysUntil)
}

// refreshKeys fetches the JWKS. Unless the keys expired, a fetch within
// minJWKSRefresh of the last one is skipped (a stream of tokens with
// unknown kids cannot make WebSSH hammer the provider); fetched reports
// whether new keys arrived. Expired keys are never used: a failed fetch
// then fails the sign-in.
func (r *remote) refreshKeys(ctx context.Context, jwksURI string) (fetched bool, err error) {
	r.fetch.Lock()
	defer r.fetch.Unlock()
	r.mu.Lock()
	now := r.s.now()
	fresh := r.keys != nil && now.Before(r.keysUntil)
	recent := !r.keysAt.IsZero() && now.Sub(r.keysAt) < minJWKSRefresh
	r.mu.Unlock()
	if fresh && recent {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, r.s.timeout())
	defer cancel()
	body, age, err := getJSON(ctx, r.client, jwksURI)
	if err != nil {
		return false, err
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return false, fmt.Errorf("%w: %w", errProvider, err)
	}
	if age == 0 {
		age = r.s.jwksMaxAge()
	}
	age = min(max(age, minJWKSAge), maxJWKSAge)
	r.mu.Lock()
	r.keys, r.keysAt, r.keysUntil = keys, now, now.Add(age)
	r.mu.Unlock()
	return true, nil
}

// verify checks the signature of an ID Token with fresh keys; a token
// signed with a key the cache does not know fetches the keys once more,
// which covers a key rotation at the provider.
func (r *remote) verify(ctx context.Context, token string) (header, []byte, error) {
	m, allowed, err := r.metadata(ctx)
	if err != nil {
		return header{}, nil, err
	}
	keys, fresh := r.currentKeys()
	if !fresh {
		if _, err := r.refreshKeys(ctx, m.JWKSURI); err != nil {
			return header{}, nil, err
		}
		keys, _ = r.currentKeys()
	}
	hdr, payload, err := verifyJWS(token, keys, allowed)
	if !errors.Is(err, errNoKey) {
		return hdr, payload, err
	}
	fetched, ferr := r.refreshKeys(ctx, m.JWKSURI)
	if ferr != nil {
		return hdr, nil, errors.Join(err, ferr)
	}
	if !fetched {
		return hdr, nil, err
	}
	keys, _ = r.currentKeys()
	return verifyJWS(token, keys, allowed)
}
