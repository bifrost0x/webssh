package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/oidc"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

// oidcArea wires the area "oidc" (ID2): OpenID Connect sign-in (internal/auth/oidc).
// ID2 fills in the hooks; no other package edits this file.
//
// The identity table exists and E05 is migrated whether or not OIDC is
// enabled; routes and the step-up method exist only with OIDC_ENABLED.
func oidcArea() extension {
	var provider *oidc.Provider
	return extension{
		name:    "oidc",
		schemas: []store.Schema{oidc.Schema()},
		prepare: func(sys *system) error {
			p, err := newOIDCProvider(sys.cfg)
			if err != nil {
				return err
			}
			provider = p
			// As in the Python release, the feature is ready when OIDC is
			// off or its provider was set up; the deployment ceiling
			// (OIDC_ENABLED) still applies.
			sys.optional.featureReady["oidc"] = operations.Readiness{Ready: true}
			return nil
		},
		wire: func(sys *system) error {
			if provider == nil {
				return nil
			}
			links := &oidc.Links{DB: sys.db}
			cfg := sys.cfg
			(&oidc.HTTP{
				Provider: provider, Links: links, Flights: &auth.Flights{}, SignIn: sys.flow,
				Accounts: oidcAccounts{sys.accounts}, StepUp: sys.stepup, Proofs: sys.stepup, Sessions: sys.sessions,
				Gates: sys.gates, Binding: httpapi.BrowserBinding,
				Limits: auth.FactorLimits{Limiter: sys.limiter, Enabled: cfg.RateLimits.Enabled,
					Login:  auth.ParseRule(cfg.OIDC.LoginRateLimit, ruleOIDCLogin),
					Reauth: auth.ParseRule(cfg.RateLimits.Reauth, ruleReauth), ClientAddr: clientAddrString},
				Root: cfg.ApplicationRoot, Audit: sys.audit, Logger: sys.log,
			}).Register(sys.edge.Mux())
			sys.stepup.External = append(sys.stepup.External, oidcStepUp{links: links, gates: sys.gates})
			return nil
		},
		migrate: func(r *legacy.Registry, _ config.Config, _ config.LookupFunc) error {
			return legacy.AddOIDCIdentities(r)
		},
	}
}

// ruleOIDCLogin is the default of OIDC_LOGIN_RATE_LIMIT.
var ruleOIDCLogin = auth.Rule{Limit: 10, Window: time.Minute}

// newOIDCProvider builds the provider from the configuration: nil without
// OIDC_ENABLED, an error (the server does not start) for an unreadable
// client secret, as init_oidc does.
func newOIDCProvider(cfg config.Config) (*oidc.Provider, error) {
	o := cfg.OIDC
	if !o.Enabled {
		return nil, nil
	}
	if o.Issuer == "" || o.ClientID == "" || o.ClientSecretFile == "" || o.RedirectURI == "" {
		return nil, fmt.Errorf("OIDC_ENABLED requires OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET_FILE, and OIDC_REDIRECT_URI")
	}
	secret, err := oidc.ReadClientSecret(o.ClientSecretFile)
	if err != nil {
		return nil, err
	}
	roots, err := cfg.CABundle.CertPool()
	if err != nil {
		return nil, fmt.Errorf("OIDC provider trust: %w", err)
	}
	return oidc.New(oidc.Settings{
		Issuer: o.Issuer, ClientID: o.ClientID, ClientSecret: secret, RedirectURI: o.RedirectURI,
		AllowedSubjects: o.AllowedSubjects, AllowedDomains: o.AllowedDomains,
		Assurance:    oidc.AssurancePolicy{MFAACR: o.MFAACR, MFAAMR: o.MFAAMR, PhishingACR: o.PhishingACR, PhishingAMR: o.PhishingAMR},
		StepUpACR:    o.StepUpACR,
		StepUpMaxAge: cfg.StepUpMaxAge,
		RootCAs:      roots,
	})
}

// oidcAccounts reads accounts for the OIDC routes.
type oidcAccounts struct{ s *accounts.Service }

func (a oidcAccounts) OIDCAccount(ctx context.Context, userID int64) (oidc.Account, error) {
	acc, err := a.s.Get(ctx, userID)
	if err != nil {
		return oidc.Account{}, err
	}
	return oidc.Account{ID: acc.ID, Username: acc.Username, Locked: acc.IsLocked, Generation: acc.AuthGeneration,
		Managed: string(acc.Managed)}, nil
}

// oidcStepUp offers the step-up at the provider to sessions that signed
// in with OIDC while the feature is on and the account still has an OIDC
// identity (account_step_up_routes._allowed_methods).
type oidcStepUp struct {
	links *oidc.Links
	gates *operations.Gates
}

func (oidcStepUp) Method() string { return "oidc" }

func (oidcStepUp) ReachesMFA() bool { return true }

func (o oidcStepUp) Offered(ctx context.Context, p principal.Principal, sa stepup.SessionAssurance) (bool, error) {
	if !slices.Contains(sa.Methods, "oidc") {
		return false, nil
	}
	if on, err := o.gates.Active(ctx, "oidc"); err != nil || !on {
		return false, nil //nolint:nilerr // a gate that cannot be read counts as off (fail closed)
	}
	return o.links.HasIdentity(ctx, p.UserID)
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ oidc.StepUp           = (*stepup.Service)(nil)
	_ oidc.ProviderStepUp   = (*stepup.Service)(nil)
	_ oidc.Sessions         = (*session.Service)(nil)
	_ oidc.Gates            = (*operations.Gates)(nil)
	_ oidc.Auditor          = (*audit.Logger)(nil)
	_ oidc.SignIn           = (*auth.Flow)(nil)
	_ stepup.ExternalMethod = oidcStepUp{}
)
