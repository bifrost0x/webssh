package oidc

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// errClaims is every refusal of the ID Token claims.
var errClaims = errors.New("oidc: id token claims invalid")

// leeway is the clock skew the Python release allowed (Authlib's
// parse_id_token, leeway 120 seconds).
const leeway = 120 * time.Second

// maxIdentifierRunes bounds issuer and subject as oidc_routes.py does.
const maxIdentifierRunes = 512

// claims are the ID Token claims WebSSH reads. Every member keeps its raw
// JSON so that a value of the wrong type is refused instead of coerced.
type claims struct {
	Issuer          string         `json:"iss"`
	Subject         jsontext.Value `json:"sub"`
	Audience        jsontext.Value `json:"aud"`
	Expiry          jsontext.Value `json:"exp"`
	IssuedAt        jsontext.Value `json:"iat"`
	NotBefore       jsontext.Value `json:"nbf"`
	Nonce           jsontext.Value `json:"nonce"`
	AuthorizedParty jsontext.Value `json:"azp"`
	AtHash          jsontext.Value `json:"at_hash"`
	Email           jsontext.Value `json:"email"`
	EmailVerified   jsontext.Value `json:"email_verified"`
	PreferredName   jsontext.Value `json:"preferred_username"`
	Name            jsontext.Value `json:"name"`
	ACR             jsontext.Value `json:"acr"`
	AMR             jsontext.Value `json:"amr"`
	AuthTime        jsontext.Value `json:"auth_time"`
}

// checked is the result of a valid ID Token.
type checked struct {
	Subject       string
	Username      string
	DisplayName   string
	Email         string
	EmailVerified bool
	// Evidence holds acr, amr and auth_time for the assurance rules.
	Evidence evidence
}

// tokenCheck is what an ID Token is checked against.
type tokenCheck struct {
	Issuer   string // the issuer of the discovery document
	ClientID string
	Nonce    string
	Now      time.Time
	// AccessToken and Alg check at_hash when the token carries one.
	AccessToken, Alg string
}

// parseClaims decodes and checks the payload of a verified ID Token (OIDC
// Core 1.0 section 3.1.3.7).
func parseClaims(payload []byte, tc tokenCheck) (checked, error) {
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return checked{}, fmt.Errorf("%w: %w", errClaims, err)
	}
	if err := c.check(tc); err != nil {
		return checked{}, err
	}
	out := checked{
		Subject: stringClaim(c.Subject), Email: stringClaim(c.Email), EmailVerified: string(c.EmailVerified) == "true",
		Username: stringClaim(c.PreferredName), DisplayName: stringClaim(c.Name),
		Evidence: c.evidence(),
	}
	return out, nil
}

// evidence is the assurance evidence of the claims.
func (c claims) evidence() evidence { return evidence{acr: c.ACR, amr: c.AMR, authTime: c.AuthTime} }

func (c claims) check(tc tokenCheck) error {
	sub, ok := strictString(c.Subject)
	switch {
	case c.Issuer == "" || c.Issuer != tc.Issuer || utf8.RuneCountInString(c.Issuer) > maxIdentifierRunes:
		return fmt.Errorf("%w: issuer", errClaims)
	case !ok || sub == "" || utf8.RuneCountInString(sub) > maxIdentifierRunes:
		return fmt.Errorf("%w: subject", errClaims)
	}
	aud, err := audience(c.Audience)
	if err != nil || !slices.Contains(aud, tc.ClientID) {
		return fmt.Errorf("%w: audience", errClaims)
	}
	// OIDC Core 3.1.3.7 items 4 and 5: with other audiences beside the
	// client, azp must be present and be the client.
	azp, azpOK := strictString(c.AuthorizedParty)
	switch {
	case len(c.AuthorizedParty) > 0 && (!azpOK || azp != tc.ClientID):
		return fmt.Errorf("%w: azp", errClaims)
	case len(aud) > 1 && len(c.AuthorizedParty) == 0:
		return fmt.Errorf("%w: azp required for several audiences", errClaims)
	}
	exp, okExp := number(c.Expiry)
	iat, okIat := number(c.IssuedAt)
	switch {
	case !okExp || !tc.Now.Before(unix(exp).Add(leeway)):
		return fmt.Errorf("%w: expired", errClaims)
	case !okIat || unix(iat).After(tc.Now.Add(leeway)):
		return fmt.Errorf("%w: issued in the future", errClaims)
	}
	if len(c.NotBefore) > 0 {
		if nbf, ok := number(c.NotBefore); !ok || unix(nbf).After(tc.Now.Add(leeway)) {
			return fmt.Errorf("%w: not yet valid", errClaims)
		}
	}
	nonce, ok := strictString(c.Nonce)
	if tc.Nonce == "" || !ok || subtle.ConstantTimeCompare([]byte(nonce), []byte(tc.Nonce)) != 1 {
		return fmt.Errorf("%w: nonce", errClaims)
	}
	if len(c.AtHash) > 0 && tc.AccessToken != "" {
		h, ok := strictString(c.AtHash)
		if !ok || !atHashMatches(h, tc.AccessToken, tc.Alg) {
			return fmt.Errorf("%w: at_hash does not match the access token", errClaims)
		}
	}
	return nil
}

// strictString returns a JSON string value; anything else is not ok.
func strictString(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

// stringClaim is a string claim, or "" for an absent or non-string one.
func stringClaim(v jsontext.Value) string {
	s, _ := strictString(v)
	return s
}

// audience accepts the string and the array form of aud (RFC 7519
// section 4.1.3).
func audience(v jsontext.Value) ([]string, error) {
	switch v.Kind() {
	case '"':
		s, _ := strictString(v)
		return []string{s}, nil
	case '[':
		var many []string
		if err := json.Unmarshal(v, &many); err != nil || len(many) == 0 || len(many) > 32 {
			return nil, errors.New("aud must be a non-empty array of strings")
		}
		return many, nil
	}
	return nil, errors.New("aud must be a string or an array of strings")
}

// number reads a NumericDate (RFC 7519 section 2): a JSON number.
func number(v jsontext.Value) (float64, bool) {
	if v.Kind() != '0' {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(v, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e15 {
		return 0, false
	}
	return f, true
}

func unix(f float64) time.Time {
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9))
}

// atHashMatches implements OIDC Core 1.0 section 3.1.3.6.
func atHashMatches(atHash, accessToken, alg string) bool {
	a, ok := algorithms[alg]
	if !ok {
		return false
	}
	if a.hash == 0 {
		// EdDSA names no hash; OIDC leaves at_hash undefined for it. The
		// token itself is signed, so the value cannot be checked.
		return true
	}
	h := a.hash.New()
	h.Write([]byte(accessToken))
	sum := h.Sum(nil)
	want := base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
	return subtle.ConstantTimeCompare([]byte(want), []byte(atHash)) == 1
}

// emailDomain is the lower-cased part after the last "@", as
// oidc_routes.py reads it; an address without "@" has no domain.
func emailDomain(email string) string {
	i := strings.LastIndexByte(email, '@')
	if i < 0 {
		return ""
	}
	return strings.ToLower(email[i+1:])
}
