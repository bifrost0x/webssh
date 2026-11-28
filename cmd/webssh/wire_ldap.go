package main

import (
	"context"
	"net/http"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/ldap"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/ldapproto"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

// ldapArea wires the area "ldap" (ID1): LDAP and Active Directory sign-in (internal/auth/ldap, internal/ldapproto).
//
// The service exists in every build: with LDAP_ENABLED false it keeps
// LDAP-managed accounts signed out, as the Python release did. A
// directory configuration that cannot be used (unreadable files, a filter
// that does not compile) leaves LDAP not ready; the server still starts
// (condition K7/A2).
func ldapArea() extension {
	var svc *ldap.Service
	return extension{
		name:    "ldap",
		schemas: []store.Schema{ldap.Schema()},
		prepare: func(sys *system) error {
			svc = newLDAPService(sys)
			sys.optional.ldapStepUp = svc
			sys.optional.sessionGate = svc.Gate
			sys.optional.featureReady["ldap"] = ldapReadiness(sys.cfg.LDAP, svc)
			return nil
		},
		wire: func(sys *system) error {
			svc.StepUp, svc.Gates = sys.stepup, sys.gates
			svc.Attempts = func(ctx context.Context, subject string) (func(), bool) {
				return sys.flow.ReserveSubjectAttempt(ctx, "ldap_login", subject)
			}
			cfg := sys.cfg
			(&ldap.HTTP{Service: svc, AdminPanel: cfg.Accounts.AdminPanelEnabled, Limits: sys.factorLimits(),
				StatusRule: auth.ParseRule(cfg.LDAP.LoginRateLimit, ruleLogin)}).Register(sys.edge.Mux())
			(&auth.DirectorySignIn{Flow: sys.flow, Provider: svc, Rule: auth.ParseRule(cfg.LDAP.LoginRateLimit, ruleLogin),
				Active: func(r *http.Request) bool { return ldapActive(r.Context(), sys, svc) }}).Register(sys.edge.Mux())
			return nil
		},
		background: func(ctx context.Context, sys *system) {
			if !sys.cfg.LDAP.Enabled || svc.Directory == nil {
				return
			}
			sys.background.Go(func() {
				sys.every(ctx, sys.cfg.LDAP.Revalidation, func(ctx context.Context) bool {
					if sys.maintenance.Load() {
						return true
					}
					if n, err := svc.Sweep(ctx); err != nil {
						sys.log.Error("LDAP background revalidation error", "err", err)
					} else if n > 0 {
						sys.log.Warn("LDAP background revalidation ended access", "accounts", n)
					}
					return true
				})
			})
		},
		migrate: func(r *legacy.Registry, _ config.Config, _ config.LookupFunc) error {
			return legacy.AddLDAP(r)
		},
	}
}

func newLDAPService(sys *system) *ldap.Service {
	cfg := sys.cfg.LDAP
	svc := &ldap.Service{DB: sys.db, Accounts: ldapAccounts{a: sys.accounts}, Sessions: sys.sessions,
		Passwords: sys.local, Audit: sys.audit, Admins: accounts.Admins(sys.cfg.Accounts.AdminUsers).Reserves,
		Enabled: cfg.Enabled, Provider: cfg.ProviderID, AutoProvision: cfg.AutoProvision, Revalidation: cfg.Revalidation,
		Logger: sys.log}
	if !cfg.Enabled {
		return svc
	}
	client, err := ldap.NewClient(ldap.Settings{Provider: cfg.ProviderID, URL: cfg.URL, BackupURL: cfg.BackupURL,
		BaseDN: cfg.BaseDN, BindDN: cfg.BindDN, BindPasswordFile: cfg.BindPasswordFile, CAFile: cfg.CAFile,
		UserFilter: cfg.UserFilter, UniqueIDAttribute: cfg.UniqueIDAttribute, ConnectTimeout: cfg.ConnectTimeout,
		OperationTimeout: cfg.OperationTimeout, Dial: ldapDial})
	if err != nil {
		sys.log.Error("LDAP sign-in is not ready", "err", err)
		return svc
	}
	svc.Directory = client
	return svc
}

// ldapDial replaces the directory dialer (end-to-end suite only); nil
// dials directly.
var ldapDial ldapproto.DialFunc

// ldapReadiness is the start-up readiness of the security feature: the
// Python release was ready when LDAP was off or its files validated.
func ldapReadiness(cfg config.LDAP, svc *ldap.Service) operations.Readiness {
	if !cfg.Enabled {
		return operations.Readiness{Ready: true}
	}
	if svc.Directory == nil {
		return operations.Readiness{Reason: "LDAP runtime validation did not complete."}
	}
	if err := svc.Directory.Ready(); err != nil {
		return operations.Readiness{Reason: "LDAP runtime validation did not complete."}
	}
	return operations.Readiness{Ready: true}
}

func ldapActive(ctx context.Context, sys *system, svc *ldap.Service) bool {
	if !sys.cfg.LDAP.Enabled || svc.Directory == nil {
		return false
	}
	on, err := sys.gates.Active(ctx, ldap.Feature)
	return err == nil && on
}

// ldapAccounts adapts the accounts to ldap.Accounts.
type ldapAccounts struct {
	a *accounts.Service
}

func (x ldapAccounts) GetTx(ctx context.Context, tx *store.Tx, userID int64) (ldap.Account, error) {
	acc, err := accounts.GetTx(ctx, tx, userID)
	if err != nil {
		return ldap.Account{}, err
	}
	return ldap.Account{ID: acc.ID, Username: acc.Username, IsAdmin: acc.IsAdmin, IsLocked: acc.IsLocked,
		Generation: acc.AuthGeneration, Managed: string(acc.Managed)}, nil
}

func (x ldapAccounts) ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (int64, error) {
	return x.a.ProvisionTx(ctx, tx, username, manager)
}

// ReleaseTx makes the account local with the new password and raises its
// generation, as unlink_ldap_identity does.
func (x ldapAccounts) ReleaseTx(ctx context.Context, tx *store.Tx, userID int64, passwordHash string) error {
	if err := x.a.ReleaseTx(ctx, tx, userID, passwordHash); err != nil {
		return err
	}
	_, err := x.a.RaiseGenerationTx(ctx, tx, userID)
	return err
}

func (x ldapAccounts) AdoptTx(ctx context.Context, tx *store.Tx, userID int64, manager string) error {
	if err := x.a.SetManagerTx(ctx, tx, userID, accounts.Manager(manager)); err != nil {
		return err
	}
	return local.RemoveTx(ctx, tx, userID)
}

func (x ldapAccounts) RaiseGenerationTx(ctx context.Context, tx *store.Tx, userID int64) error {
	_, err := x.a.RaiseGenerationTx(ctx, tx, userID)
	return err
}

func (x ldapAccounts) BreakGlassAdminTx(ctx context.Context, tx *store.Tx) (bool, error) {
	return x.a.BreakGlassAdminTx(ctx, tx)
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ ldap.Sessions    = (*session.Service)(nil)
	_ ldap.StepUp      = (*stepup.Service)(nil)
	_ ldap.Accounts    = ldapAccounts{}
	_ ldap.Passwords   = (*local.Provider)(nil)
	_ ldap.Gates       = (*operations.Gates)(nil)
	_ ldap.Directory   = (*ldap.Client)(nil)
	_ stepup.Directory = (*ldap.Service)(nil)
	_ auth.Provider    = (*ldap.Service)(nil)
)
