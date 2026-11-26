package oidc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
)

// Provider is the OIDC sign-in provider (auth.ExternalProvider). It holds
// no per-request state: state, nonce and PKCE verifier travel in the
// auth.Flight that the flow stores server-side.
type Provider struct {
	s      Settings
	remote *remote
}

var _ auth.ExternalProvider = (*Provider)(nil)

// New checks the settings and returns the provider. It does not contact
// the provider: discovery runs on the first sign-in, so an unreachable
// provider never stops the server.
func New(s Settings) (*Provider, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &Provider{s: s, remote: newRemote(s)}, nil
}

// Name implements auth.ExternalProvider.
func (*Provider) Name() auth.ProviderName { return auth.ProviderOIDC }

// Issuer is the configured issuer, under which identities are stored.
func (p *Provider) Issuer() string { return p.s.Issuer }

// stepUpACR is the acr_values of a step-up: the configured values,
// sorted and joined as begin_oidc_step_up does.
func (p *Provider) stepUpACR() string {
	v := slices.Clone(p.s.StepUpACR)
	slices.Sort(v)
	return strings.Join(slices.Compact(v), " ")
}

// Begin implements auth.ExternalProvider. Link and step-up ask the
// provider to authenticate again; a step-up also asks for a fresh
// authentication (max_age=0) and for OIDC_STEP_UP_ACR_VALUES.
func (p *Provider) Begin(ctx context.Context, f auth.Flight) (string, error) {
	return p.begin(ctx, f, f.Purpose == auth.PurposeStepUp)
}

// begin builds the authorization URL; requestACR adds acr_values.
func (p *Provider) begin(ctx context.Context, f auth.Flight, requestACR bool) (string, error) {
	if f.Provider != auth.ProviderOIDC || f.State == "" || f.Nonce == "" || f.Verifier == "" {
		return "", fault.New(fault.InvalidRequest, "")
	}
	a := authRequest{state: f.State, nonce: f.Nonce, verifier: f.Verifier}
	switch f.Purpose {
	case auth.PurposeSignIn:
	case auth.PurposeLink:
		a.prompt = "login"
	case auth.PurposeStepUp:
		a.prompt, a.maxAge = "login", "0"
		if requestACR {
			a.acr = p.stepUpACR()
		}
	default:
		return "", fault.New(fault.InvalidRequest, "")
	}
	u, err := p.remote.authCodeURL(ctx, a)
	if err != nil {
		return "", unavailable(err)
	}
	return u, nil
}

// Complete implements auth.ExternalProvider.
func (p *Provider) Complete(ctx context.Context, f auth.Flight, cb auth.Callback) (auth.Identity, error) {
	res, err := p.complete(ctx, f, cb)
	return res.identity, err
}

// result is a completed callback: the identity and the assurance evidence
// the step-up rules need.
type result struct {
	identity   auth.Identity
	assessment Assessment
}

// complete runs every check of a callback (OIDC Core 1.0 section 3.1.3):
// the flight (state, expiry, provider error), the code exchange with the
// PKCE verifier, the signature, the claims with nonce, audience and
// authorized party, and the allowlists.
func (p *Provider) complete(ctx context.Context, f auth.Flight, cb auth.Callback) (result, error) {
	if f.Provider != auth.ProviderOIDC {
		return result{}, refused()
	}
	if err := f.Accept(cb, p.s.now()); err != nil {
		return result{}, err
	}
	raw, access, err := p.remote.exchange(ctx, cb.Code, f.Verifier)
	if err != nil {
		return result{}, classify(err)
	}
	hdr, payload, err := p.remote.verify(ctx, raw)
	if err != nil {
		return result{}, classify(err)
	}
	m, _, err := p.remote.metadata(ctx)
	if err != nil {
		return result{}, classify(err)
	}
	c, err := parseClaims(payload, tokenCheck{Issuer: m.Issuer, ClientID: p.s.ClientID, Nonce: f.Nonce,
		Now: p.s.now(), AccessToken: access, Alg: hdr.Alg})
	if err != nil {
		return result{}, classify(err)
	}
	if err := p.admit(c); err != nil {
		return result{}, err
	}
	a := p.s.Assurance.assess(c.Evidence)
	id := auth.Identity{
		Provider: auth.ProviderOIDC, Issuer: p.s.Issuer, Subject: c.Subject,
		Username: c.Username, DisplayName: c.DisplayName, Email: c.Email, EmailVerified: c.EmailVerified,
		Assurance: a.Level, Methods: a.AMR,
	}
	return result{identity: id, assessment: a}, nil
}

// errNotAllowed marks an identity outside the allowlists.
var errNotAllowed = errors.New("oidc: identity not allowed")

// admit applies OIDC_ALLOWED_SUBJECTS and OIDC_ALLOWED_DOMAINS. A domain
// only counts with email_verified exactly true.
func (p *Provider) admit(c checked) error {
	if len(p.s.AllowedSubjects) > 0 && !slices.Contains(p.s.AllowedSubjects, c.Subject) {
		return fault.Wrap(fault.AuthFailed, errNotAllowed, "")
	}
	if len(p.s.AllowedDomains) > 0 && (!c.EmailVerified || !slices.Contains(p.s.AllowedDomains, emailDomain(c.Email))) {
		return fault.Wrap(fault.AuthFailed, errNotAllowed, "")
	}
	return nil
}

// fresh reports whether a step-up answer proves a new authentication:
// an auth_time at most StepUpMaxAge old (and not in the future beyond the
// clock leeway), and, when acr was asked for, one of the asked values.
func (p *Provider) fresh(a Assessment, requestedACR bool) bool {
	if a.AuthTime.IsZero() {
		return false
	}
	age := p.s.now().Truncate(time.Second).Sub(a.AuthTime)
	if age < 0 || age > p.s.StepUpMaxAge {
		return false
	}
	if requestedACR && len(p.s.StepUpACR) > 0 && !slices.Contains(p.s.StepUpACR, a.ACR) {
		return false
	}
	return true
}

func refused() error { return fault.New(fault.AuthFailed, "") }

func unavailable(err error) error {
	return fault.Wrap(fault.Unavailable, err, "Identity provider unavailable")
}

// classify maps a provider failure to the two answers of the contract:
// an unreachable or broken provider is unavailable, every refusal of the
// code or the token is auth_failed. The detail stays in the wrapped error
// for the log.
func classify(err error) error {
	if errors.Is(err, errProvider) {
		return unavailable(err)
	}
	return fault.Wrap(fault.AuthFailed, err, "")
}
