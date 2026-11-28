package github

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Service is GitHub sign-in. It is safe for concurrent use.
type Service struct {
	DB       *store.DB
	Ring     Ring
	Accounts Accounts
	SignIn   SignIn
	StepUp   StepUp
	Passkeys Passkeys
	Admins   AdminNames
	Client   Client
	// Binding is the browser binding of the HTTP edge
	// (httpapi.BrowserBinding); flights are tied to it.
	Binding BindingFunc
	// FirstAccountHost reports whether the host of a request may create
	// the first account (httpapi.FirstAccountHost), as for the bootstrap
	// registration; nil allows every host.
	FirstAccountHost HostFunc
	// Limits rates the sign-in routes ("5 per minute" per client).
	Limits auth.FactorLimits
	// Root is APPLICATION_ROOT; the callback path of redirect_uri lies
	// below it.
	Root string
	// Production is DEPLOYMENT_PROFILE=production: provisioning needs an
	// organization allowlist there.
	Production bool
	Audit      auth.Audit
	Logger     *slog.Logger
	Now        func() time.Time
}

var _ auth.ExternalProvider = (*Service)(nil)
var _ auth.IdentityLinks = (*Service)(nil)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Service) audit() auth.Audit { return auth.AuditOrLog(s.Audit, s.Logger) }

// Name implements auth.ExternalProvider.
func (*Service) Name() auth.ProviderName { return auth.ProviderGitHub }

// Begin implements auth.ExternalProvider: the authorization URL of the
// active configuration for the flight's state and PKCE challenge.
func (s *Service) Begin(ctx context.Context, f auth.Flight) (string, error) {
	cfg, err := s.Configuration(ctx)
	if err != nil {
		return "", err
	}
	if !cfg.Active {
		return "", fault.New(fault.NotFound, "")
	}
	if f.Provider != auth.ProviderGitHub || f.State == "" || f.Verifier == "" {
		return "", fault.New(fault.InvalidRequest, "")
	}
	return s.Client.AuthorizationURL(cfg.ClientID, cfg.RedirectURI, f.State, f.Challenge()), nil
}

// Complete implements auth.ExternalProvider: Flight.Accept, then the code
// exchange with the verifier, the profile and the organization policy. A
// state or configuration that is not valid is fault.AuthFailed, GitHub
// that cannot be asked fault.Unavailable, a missing organization
// membership fault.Forbidden.
func (s *Service) Complete(ctx context.Context, f auth.Flight, cb auth.Callback) (auth.Identity, error) {
	cfg, secret, err := s.active(ctx)
	if err != nil {
		return auth.Identity{}, classify(err)
	}
	p, err := s.complete(ctx, cfg, secret, f, cb)
	if err != nil {
		return auth.Identity{}, classify(err)
	}
	return auth.Identity{Provider: auth.ProviderGitHub, Subject: p.UserID, Username: p.Login, DisplayName: p.DisplayName,
		Assurance: auth.AssuranceBasic, Methods: []string{"github"}}, nil
}

func (s *Service) complete(ctx context.Context, cfg Configuration, secret string, f auth.Flight, cb auth.Callback) (Profile, error) {
	if err := f.Accept(cb, s.now()); err != nil {
		return Profile{}, errState
	}
	token, err := s.Client.Exchange(ctx, cfg.ClientID, secret, cfg.RedirectURI, cb.Code, f.Verifier)
	if err != nil {
		return Profile{}, err
	}
	p, err := s.Client.FetchProfile(ctx, token)
	if err != nil {
		return Profile{}, err
	}
	if err := s.Client.EnforceOrganizations(ctx, token, cfg.AllowedOrgs); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// classify maps the package's errors to the contract's codes.
func classify(err error) error {
	var ce *errConfig
	switch {
	case errors.Is(err, errOrganization):
		return fault.Wrap(fault.Forbidden, err, "GitHub organization membership is required")
	case errors.Is(err, errProvider):
		return fault.Wrap(fault.Unavailable, err, "GitHub authentication is temporarily unavailable")
	case errors.Is(err, errState), errors.As(err, &ce):
		return fault.Wrap(fault.AuthFailed, err, "")
	}
	return err
}
