package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxResponseBytes bounds every provider response (discovery, JWKS, token).
const maxResponseBytes = 1 << 20

// errProvider means that the provider could not be asked safely; the
// sign-in fails closed as unavailable.
var errProvider = errors.New("oidc: identity provider unavailable")

// newHTTPClient is the client of every provider request: a bounded
// timeout, TLS 1.2 or later, the proxy of the environment as the Python
// release (requests) used it, and no redirects: a provider answer cannot
// send WebSSH to another host, not even one that resolves and answers.
func newHTTPClient(timeout time.Duration, roots *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	transport.Proxy = http.ProxyFromEnvironment
	transport.ResponseHeaderTimeout = timeout
	transport.MaxResponseHeaderBytes = 64 << 10
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// getJSON fetches url and returns the body of a 200 JSON answer with its
// Cache-Control max-age (zero when absent).
func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errProvider, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req) // #nosec G704 -- the issuer is operator configuration; endpoints are checked against it
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errProvider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: %s answered %d", errProvider, url, resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != "application/jwk-set+json") {
		return nil, 0, fmt.Errorf("%w: %s is not JSON", errProvider, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errProvider, err)
	}
	if len(body) > maxResponseBytes {
		return nil, 0, fmt.Errorf("%w: %s answer too large", errProvider, url)
	}
	return body, maxAge(resp.Header.Get("Cache-Control")), nil
}

// maxAge reads max-age of a Cache-Control header; no-store and no-cache
// count as zero, so the default lifetime applies.
func maxAge(cc string) time.Duration {
	for part := range strings.SplitSeq(cc, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch strings.ToLower(name) {
		case "no-store", "no-cache":
			return 0
		case "max-age":
			if n, err := strconv.Atoi(strings.Trim(value, `"`)); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}
