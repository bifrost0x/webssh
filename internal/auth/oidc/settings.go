package oidc

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

// Settings are the documented OIDC_* variables (config.py) and what the
// composition root derives for them.
type Settings struct {
	// Issuer is OIDC_ISSUER without a trailing slash. Identities are
	// stored under it.
	Issuer       string
	ClientID     string // OIDC_CLIENT_ID
	ClientSecret string // the content of OIDC_CLIENT_SECRET_FILE
	RedirectURI  string // OIDC_REDIRECT_URI, ending in /oidc/callback
	// AllowedSubjects (OIDC_ALLOWED_SUBJECTS) and AllowedDomains
	// (OIDC_ALLOWED_DOMAINS, lower case) admit only matching identities;
	// empty admits every identity of the issuer.
	AllowedSubjects []string
	AllowedDomains  []string
	Assurance       AssurancePolicy
	// StepUpACR is OIDC_STEP_UP_ACR_VALUES, asked for in a step-up and
	// required in its answer.
	StepUpACR []string
	// StepUpMaxAge is STEP_UP_MAX_AGE_SECONDS: a step-up needs an auth_time
	// at most this old.
	StepUpMaxAge time.Duration
	// HTTPTimeout bounds each request to the provider (OIDC_HTTP_TIMEOUT,
	// five seconds in the Python release).
	HTTPTimeout time.Duration
	// RootCAs verifies the provider (REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE or
	// the system roots when nil).
	RootCAs *x509.CertPool
	// JWKSMaxAge bounds how long fetched keys are used before they are
	// fetched again; zero is DefaultJWKSMaxAge.
	JWKSMaxAge time.Duration
	Now        func() time.Time

	// insecureLoopback admits an http issuer on a loopback address. Only
	// the lab test against mock-oauth2 sets it; the configuration refuses
	// such issuers as the Python release does.
	insecureLoopback bool
}

// DefaultJWKSMaxAge is the lifetime of fetched keys without a usable
// Cache-Control max-age.
const DefaultJWKSMaxAge = 15 * time.Minute

const defaultHTTPTimeout = 5 * time.Second

// maxSecretBytes bounds the client secret file.
const maxSecretBytes = 4096

// ReadClientSecret reads OIDC_CLIENT_SECRET_FILE as init_oidc does: the
// content without surrounding white space, which must not be empty.
func ReadClientSecret(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- OIDC_CLIENT_SECRET_FILE, set by the operator
	if err != nil {
		return "", fmt.Errorf("oidc: client secret file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("oidc: client secret file: %w", err)
	}
	if len(data) > maxSecretBytes {
		return "", errors.New("oidc: client secret file is too large")
	}
	secret := string(bytes.TrimSpace(data))
	if secret == "" {
		return "", errors.New("oidc: client secret file is empty")
	}
	return secret, nil
}

func (s Settings) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Settings) timeout() time.Duration {
	if s.HTTPTimeout > 0 {
		return s.HTTPTimeout
	}
	return defaultHTTPTimeout
}

func (s Settings) jwksMaxAge() time.Duration {
	if s.JWKSMaxAge > 0 {
		return s.JWKSMaxAge
	}
	return DefaultJWKSMaxAge
}

// validate checks what the provider relies on. The configuration package
// has already applied the Python start-up checks to issuer and redirect.
func (s Settings) validate() error {
	if err := s.checkEndpoint(s.Issuer); err != nil {
		return fmt.Errorf("oidc: OIDC_ISSUER: %w", err)
	}
	if strings.HasSuffix(s.Issuer, "/") {
		return errors.New("oidc: OIDC_ISSUER must not end with a slash")
	}
	if s.ClientID == "" || s.ClientSecret == "" {
		return errors.New("oidc: client id and secret are required")
	}
	u, err := url.Parse(s.RedirectURI)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasSuffix(u.Path, "/oidc/callback") {
		return errors.New("oidc: OIDC_REDIRECT_URI must be the exact /oidc/callback URL")
	}
	return nil
}

// checkEndpoint admits absolute https URLs without user information or
// fragment.
func (s Settings) checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%q is not an absolute URL without user information", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if h := u.Hostname(); s.insecureLoopback && u.Scheme == "http" && (h == "127.0.0.1" || h == "localhost" || h == "::1") {
		return nil
	}
	return fmt.Errorf("%q must use https", raw)
}
