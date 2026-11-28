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
	// metadataRetry is how long an old discovery document is served
	// without a network attempt after a refresh failed.
	metadataRetry = 30 * time.Second
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

	fetch chan struct{} // holds one token per network fetch; see lockFetch

	mu        sync.Mutex
	meta      metadata
	allowed   map[string]bool
	metaAt    time.Time
	metaFail  time.Time // when the last fetch failed, with or without an old document
	keys      []jwk
	keysAt    time.Time // when the keys were fetched
	keysUntil time.Time // when they must be fetched again
}

func newRemote(s Settings) *remote {
	return &remote{s: s, client: newHTTPClient(s.timeout(), s.RootCAs), fetch: make(chan struct{}, 1)}
}

// lockFetch waits for the one network fetch slot, or for ctx: a request
// context has no deadline of its own, but a caller that gives up must not
// stay queued behind a slow provider.
func (r *remote) lockFetch(ctx context.Context) error {
	select {
	case r.fetch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *remote) unlockFetch() { <-r.fetch }

// metadata returns the discovery document, fetching it when it is
// missing or old. A failed refresh keeps a document fetched before; a
// failed first fetch is answered without a new attempt for metadataRetry.
func (r *remote) metadata(ctx context.Context) (metadata, map[string]bool, error) {
	if m, a, ok, err := r.cachedMeta(); ok || err != nil {
		return m, a, err
	}
	if err := r.lockFetch(ctx); err != nil {
		return metadata{}, nil, err
	}
	defer r.unlockFetch()
	if m, a, ok, err := r.cachedMeta(); ok || err != nil {
		return m, a, err
	}
	m, allowed, err := r.discover(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		if !r.metaAt.IsZero() {
			r.metaFail = r.s.now()
			return r.meta, r.allowed, nil
		}
		// A caller that gave up says nothing about the provider.
		if ctx.Err() == nil {
			r.metaFail = r.s.now()
		}
		return metadata{}, nil, err
	}
	r.meta, r.allowed, r.metaAt, r.metaFail = m, allowed, r.s.now(), time.Time{}
	return m, allowed, nil
}

// cachedMeta returns the document while it is fresh, and an old one for
// metadataRetry after its refresh failed, so that sign-ins do not each
// wait for an unreachable provider. Without any document, a fetch that
// failed within metadataRetry is reported as errProvider.
func (r *remote) cachedMeta() (metadata, map[string]bool, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.s.now()
	failedRecently := !r.metaFail.IsZero() && now.Sub(r.metaFail) < metadataRetry
	switch {
	case r.metaAt.IsZero() && failedRecently:
		return metadata{}, nil, false, fmt.Errorf("%w: discovery failed within the last %s", errProvider, metadataRetry)
	case r.metaAt.IsZero():
		return metadata{}, nil, false, nil
	case now.Sub(r.metaAt) < metadataMaxAge, failedRecently:
		return r.meta, r.allowed, true, nil
	}
	return metadata{}, nil, false, nil
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
	if err := r.lockFetch(ctx); err != nil {
		return false, err
	}
	defer r.unlockFetch()
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
