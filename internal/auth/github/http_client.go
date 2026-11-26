package github

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// GitHub endpoints, defaults of Client. The web and API base URLs can be
// changed for a test double of GitHub; production uses github.com
// (GitHub Enterprise is not supported, decision of the M2 plan).
const (
	DefaultWebURL = "https://github.com"
	DefaultAPIURL = "https://api.github.com"
	apiVersion    = "2022-11-28"
	userAgent     = "WebSSH-GitHub-Authentication"
	// requestTimeout is HTTP_TIMEOUT of the Python release, per request.
	requestTimeout   = 5 * time.Second
	maxResponseBytes = 1 << 20
	maxCodeBytes     = 1024
	maxLoginChars    = 128
	maxNameChars     = 256
)

var (
	// errProvider is GitHubProviderError: GitHub could not be queried
	// safely (503).
	errProvider = errors.New("github: provider unavailable")
	// errOrganization is GitHubOrganizationRejected (403).
	errOrganization = errors.New("github: organization membership is required")
)

// Client talks to GitHub. The zero value uses github.com with the system
// trust store; HTTP may carry another transport (REQUESTS_CA_BUNDLE).
type Client struct {
	WebURL, APIURL string
	// HTTP is the client for every request. Redirects are never
	// followed, like allow_redirects=False in the Python release.
	HTTP *http.Client
}

func (c *Client) web() string {
	if c.WebURL == "" {
		return DefaultWebURL
	}
	return strings.TrimRight(c.WebURL, "/")
}

func (c *Client) api() string {
	if c.APIURL == "" {
		return DefaultAPIURL
	}
	return strings.TrimRight(c.APIURL, "/")
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if cp.Timeout == 0 || cp.Timeout > requestTimeout {
		cp.Timeout = requestTimeout
	}
	return cp.Do(req) // #nosec G704 -- the URL is the configured GitHub base, never user input
}

// AuthorizationURL is authorization_url: client id, redirect URI, state
// and the PKCE S256 challenge, no scope (a GitHub App grants access by
// its permissions).
func (c *Client) AuthorizationURL(clientID, redirectURI, state, challenge string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	// urlencode keeps the order of its argument; url.Values sorts, so the
	// query is written by hand in the Python order.
	var b strings.Builder
	for i, k := range []string{"client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method"} {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(k) + "=" + url.QueryEscape(q.Get(k)))
	}
	return c.web() + "/login/oauth/authorize?" + b.String()
}

func setHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", userAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func readBody(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("github: response too large")
	}
	return body, nil
}

// object decodes a JSON object; anything else is nil.
func object(body []byte) map[string]jsontext.Value {
	var m map[string]jsontext.Value
	if decodeJSON(body, &m) != nil {
		return nil
	}
	return m
}

// Exchange is exchange_code: it redeems the code for a user access token
// with the verifier. Every failure is errProvider.
func (c *Client) Exchange(ctx context.Context, clientID, secret, redirectURI, code, verifier string) (string, error) {
	if code == "" || len(code) > maxCodeBytes {
		return "", fmt.Errorf("%w: authorization code is invalid", errProvider)
	}
	form := url.Values{"client_id": {clientID}, "client_secret": {secret}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.web()+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %w", errProvider, err)
	}
	setHeaders(req, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.do(req)
	if err != nil {
		return "", fmt.Errorf("%w: token exchange: %w", errProvider, err)
	}
	body, err := readBody(resp)
	if err != nil {
		return "", fmt.Errorf("%w: token exchange: %w", errProvider, err)
	}
	m := object(body)
	token, ok := jsonString(m["access_token"])
	if resp.StatusCode != http.StatusOK || !ok || token == "" {
		return "", fmt.Errorf("%w: token exchange failed", errProvider)
	}
	return token, nil
}

func jsonString(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	var s string
	if decodeJSON(v, &s) != nil {
		return "", false
	}
	return s, true
}

func (c *Client) get(ctx context.Context, token, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api()+path, nil)
	if err != nil {
		return 0, nil, err
	}
	setHeaders(req, token)
	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	body, err := readBody(resp)
	return resp.StatusCode, body, err
}

// Profile is the GitHub identity: the numeric id is the key, never the
// login.
type Profile struct {
	UserID      string // decimal, as github_user_id stores it
	Login       string
	DisplayName string // "" when absent or unusable (None)
}

// FetchProfile is fetch_profile: GET /user with the Python checks. Lengths
// are counted in characters, as Python's len() does (condition K7).
func (c *Client) FetchProfile(ctx context.Context, token string) (Profile, error) {
	status, body, err := c.get(ctx, token, "/user")
	if err != nil {
		return Profile{}, fmt.Errorf("%w: profile request: %w", errProvider, err)
	}
	return parseProfile(status, body)
}

// parseProfile checks a GET /user answer. Python requires a JSON integer
// (1001.0, "1001" and true are refused) above zero, a non-empty login of
// at most 128 characters; a name that is not a non-empty string of at
// most 256 characters is dropped.
func parseProfile(status int, body []byte) (Profile, error) {
	m := object(body)
	if status != http.StatusOK || m == nil {
		return Profile{}, fmt.Errorf("%w: profile response is invalid", errProvider)
	}
	id, ok := jsonInteger(m["id"])
	login, okLogin := jsonString(m["login"])
	if !ok || !okLogin || login == "" || utf8.RuneCountInString(login) > maxLoginChars {
		return Profile{}, fmt.Errorf("%w: profile response is invalid", errProvider)
	}
	p := Profile{UserID: id, Login: login}
	if name, ok := jsonString(m["name"]); ok && name != "" && utf8.RuneCountInString(name) <= maxNameChars {
		p.DisplayName = name
	}
	return p, nil
}

// jsonInteger returns the decimal form of a positive JSON integer. Python
// reads any number without fraction or exponent as int, of any size.
func jsonInteger(v jsontext.Value) (string, bool) {
	s := string(v)
	if v.Kind() != '0' || s == "" || strings.ContainsAny(s, ".eE") {
		return "", false
	}
	neg := strings.HasPrefix(s, "-")
	digits := strings.TrimPrefix(s, "-")
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	digits = strings.TrimLeft(digits, "0")
	if neg || digits == "" {
		return "", false
	}
	return digits, true
}

// EnforceOrganizations is enforce_organization_policy: any allowed
// organization with an active membership admits the user. A 404 or a
// membership that is not active is a definite "no"; any other answer
// makes the decision uncertain, which fails closed as errProvider instead
// of a rejection.
func (c *Client) EnforceOrganizations(ctx context.Context, token string, orgs []string) error {
	if len(orgs) == 0 {
		return nil
	}
	uncertain := false
	for _, org := range orgs {
		status, body, err := c.get(ctx, token, "/user/memberships/orgs/"+url.PathEscape(org))
		if err != nil {
			uncertain = true
			continue
		}
		switch status {
		case http.StatusOK:
			m := object(body)
			if m == nil {
				// Python fails with an exception here; fail closed.
				uncertain = true
				continue
			}
			if state, _ := jsonString(m["state"]); state == "active" {
				return nil
			}
		case http.StatusNotFound:
		default:
			uncertain = true
		}
	}
	if uncertain {
		return fmt.Errorf("%w: organization membership could not be verified", errProvider)
	}
	return errOrganization
}
