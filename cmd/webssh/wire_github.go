package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/store"
)

// githubArea wires the area "github" (ID3): GitHub sign-in and the factor bootstrap (internal/auth/github).
// ID3 fills in the hooks; no other package edits this file.
//
// The migration steps of E04 and E06 are part of the release's registry
// (legacy.RegisterM1), which must cover every entity on its own.
func githubArea() extension {
	var svc *github.Service
	return extension{
		name:    "github",
		schemas: []store.Schema{github.Schema()},
		prepare: func(sys *system) error {
			client, err := githubHTTPClient(sys.cfg)
			if err != nil {
				return err
			}
			svc = &github.Service{DB: sys.db, Ring: sys.ring, Accounts: githubAccounts{sys.accounts},
				Admins: sys.accounts.Admins, Client: github.Client{HTTP: client}, Binding: httpapi.BrowserBinding,
				Root: sys.cfg.ApplicationRoot, Production: sys.cfg.Profile == config.ProfileProduction,
				Audit: authAudit{sys.audit}, Logger: sys.log}
			sys.optional.githubActive = svc.Active
			sys.optional.githubIdentity = githubCredential(svc)
			return nil
		},
		wire: func(sys *system) error {
			svc.SignIn = sys.flow
			svc.StepUp = sys.stepup
			svc.Limits = sys.factorLimits()
			if sys.optional.passkeyCount != nil {
				svc.Passkeys = sys.optional.passkeyCount
			}
			sys.stepup.Bootstrap = newBootstrap(sys.db, sys.ring, sys.accounts, sys.totp, sys.optional.passkeyCount)
			svc.Register(sys.edge.Mux())
			(&stepup.HTTP{Service: sys.stepup, Limits: sys.factorLimits(), Logger: sys.log}).RegisterBootstrap(sys.edge.Mux())
			return nil
		},
	}
}

// githubHTTPClient is the outbound client of GitHub sign-in: the system
// trust store plus REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE.
func githubHTTPClient(cfg config.Config) (*http.Client, error) {
	pool, err := cfg.CABundle.CertPool()
	if err != nil {
		return nil, fmt.Errorf("GitHub sign-in: %s: %w", cfg.CABundle.Variable, err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	return &http.Client{Transport: transport}, nil
}

// newBootstrap is the factor bootstrap of GitHub-created accounts.
func newBootstrap(db *store.DB, mac auth.MAC, acc *accounts.Service, totp auth.DurableFactor, passkeys auth.DurableFactor) *auth.Bootstrap {
	return &auth.Bootstrap{DB: db, MAC: mac, Standing: bootstrapStanding{accounts: acc, totp: totp, passkeys: passkeys}}
}

// githubAccounts adapts internal/accounts to github.Accounts.
type githubAccounts struct{ s *accounts.Service }

func (a githubAccounts) AccountTx(ctx context.Context, tx *store.Tx, userID int64) (github.Account, error) {
	acc, err := a.s.GetTx(ctx, tx, userID)
	if err != nil {
		return github.Account{}, err
	}
	return github.Account{ID: acc.ID, Username: acc.Username, Locked: acc.IsLocked, Generation: acc.AuthGeneration,
		Managed: string(acc.Managed)}, nil
}

func (a githubAccounts) ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (int64, error) {
	return a.s.ProvisionTx(ctx, tx, username, manager)
}

func (a githubAccounts) ReleaseTx(ctx context.Context, tx *store.Tx, userID int64, passwordHash string) error {
	return a.s.ReleaseTx(ctx, tx, userID, passwordHash)
}

// bootstrapStanding is user_is_eligible: an active GitHub-managed account
// with its identity, without MFA, passkeys or active authenticators.
type bootstrapStanding struct {
	accounts       *accounts.Service
	totp, passkeys auth.DurableFactor
}

func (b bootstrapStanding) BootstrapStanding(ctx context.Context, tx *store.Tx, userID int64) (int64, bool, error) {
	acc, err := b.accounts.GetTx(ctx, tx, userID)
	if fault.Is(err, fault.NotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if acc.IsLocked || acc.MFARequired || acc.Managed != accounts.ManagedGitHub {
		return 0, false, nil
	}
	if _, found, err := github.IdentityOfTx(ctx, tx, userID); err != nil || !found {
		return 0, false, err
	}
	for _, f := range []auth.DurableFactor{b.totp, b.passkeys} {
		if f == nil {
			continue
		}
		if n, err := f.Count(ctx, tx, userID); err != nil || n > 0 {
			return 0, false, err
		}
	}
	return acc.AuthGeneration, true, nil
}

// githubCredential lists an account's GitHub identity for the impact
// preview of the security feature gates.
func githubCredential(svc *github.Service) func(ctx context.Context, userID int64) (*operations.Credential, error) {
	return func(ctx context.Context, userID int64) (*operations.Credential, error) {
		i, found, err := svc.Identity(ctx, userID)
		if err != nil || !found {
			return nil, err
		}
		return &operations.Credential{ID: i.ID, CreatedAt: isoTime(i.CreatedAt)}, nil
	}
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ github.StepUp         = (*stepup.Service)(nil)
	_ github.SignIn         = (*auth.Flow)(nil)
	_ github.AdminNames     = accounts.Admins(nil)
	_ stepup.Bootstrap      = (*auth.Bootstrap)(nil)
	_ auth.ExternalProvider = (*github.Service)(nil)
)
