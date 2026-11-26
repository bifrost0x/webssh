package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/oauth2"
)

// errCodeRejected means that the token endpoint refused the code, for
// example a replayed code or a wrong PKCE verifier.
var errCodeRejected = errors.New("oidc: authorization code rejected")

// maxCodeBytes bounds an authorization code before it is sent anywhere.
const maxCodeBytes = 2048

// authRequest are the extras of one authorization request.
type authRequest struct {
	state, nonce, verifier string
	prompt, maxAge, acr    string
}

func (r *remote) oauth2Config(m metadata) *oauth2.Config {
	style := oauth2.AuthStyleInHeader
	// client_secret_basic is the default of RFC 6749 and of Authlib; a
	// provider that offers only client_secret_post gets the secret in the
	// form.
	if len(m.TokenAuthMethods) > 0 && !slices.Contains(m.TokenAuthMethods, "client_secret_basic") &&
		slices.Contains(m.TokenAuthMethods, "client_secret_post") {
		style = oauth2.AuthStyleInParams
	}
	return &oauth2.Config{
		ClientID:     r.s.ClientID,
		ClientSecret: r.s.ClientSecret,
		RedirectURL:  r.s.RedirectURI,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     oauth2.Endpoint{AuthURL: m.AuthorizationEndpoint, TokenURL: m.TokenEndpoint, AuthStyle: style},
	}
}

// authCodeURL builds the authorization request with PKCE (S256) and nonce.
func (r *remote) authCodeURL(ctx context.Context, a authRequest) (string, error) {
	m, _, err := r.metadata(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(a.verifier),
		oauth2.SetAuthURLParam("nonce", a.nonce),
	}
	for name, v := range map[string]string{"prompt": a.prompt, "max_age": a.maxAge, "acr_values": a.acr} {
		if v != "" {
			opts = append(opts, oauth2.SetAuthURLParam(name, v))
		}
	}
	return r.oauth2Config(m).AuthCodeURL(a.state, opts...), nil
}

// exchange redeems code with the PKCE verifier and returns the raw ID
// Token and the access token. A response without ID Token is refused.
func (r *remote) exchange(ctx context.Context, code, verifier string) (idToken, accessToken string, err error) {
	if code == "" || len(code) > maxCodeBytes {
		return "", "", errCodeRejected
	}
	m, _, err := r.metadata(ctx)
	if err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(ctx, r.s.timeout())
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, r.client)
	tok, err := r.oauth2Config(m).Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok && re.ErrorCode != "" {
			return "", "", fmt.Errorf("%w: %s", errCodeRejected, re.ErrorCode)
		}
		return "", "", fmt.Errorf("%w: token endpoint: %w", errProvider, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", "", fmt.Errorf("%w: the token response has no id_token", errClaims)
	}
	return raw, tok.AccessToken, nil
}
