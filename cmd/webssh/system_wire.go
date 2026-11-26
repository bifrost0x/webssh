package main

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/terminal"
	"github.com/bifrost0x/webssh/internal/vault"
)

// The step-up service is the one provider of every consumer's StepUp
// interface; capabilities do not import each other, so the composition
// root checks the fit at compile time.
var (
	_ vault.StepUp      = (*stepup.Service)(nil)
	_ hostkey.StepUp    = (*stepup.Service)(nil)
	_ operations.StepUp = (*stepup.Service)(nil)
	_ accounts.StepUp   = (*stepup.Service)(nil)
	_ auth.StepUp       = (*stepup.Service)(nil)
	_ totp.StepUp       = (*stepup.Service)(nil)

	_ terminal.Profiles    = (*hosts.Service)(nil)
	_ terminal.SavedRoutes = (*hosts.Service)(nil)
	_ hosts.Keys           = (*vault.Service)(nil)
	_ client.KeySource     = (*vault.Service)(nil)
	_ client.HostKeys      = (*hostkey.Store)(nil)
	_ client.Network       = (*netpolicy.Policy)(nil)
	_ auth.Auditor         = (*audit.Logger)(nil)
)

// buildCapabilities wires the factors, step-up, sign-in flow, saved hosts,
// keys, host keys, network policy and terminal.
func (s *system) buildCapabilities(in bootInput) error {
	cfg := s.cfg
	opt := &s.optional
	gates := &operations.Gates{DB: s.db, Deployment: featureDeployment(cfg, in.lookup), Ready: maps.Clone(opt.featureReady), Audit: s.audit}
	s.gates = gates
	authAudit := authAudit{s.audit}
	s.recovery = &auth.Recovery{DB: s.db}
	s.throttle = &auth.Throttle{DB: s.db}
	s.mfa = &auth.MFA{DB: s.db, Accounts: mfaAccounts{s.accounts}, Gates: gates, Passkeys: opt.passkeyCount,
		Sessions: s.sessions, Audit: authAudit, Logger: s.log}
	s.totp = &totp.Service{DB: s.db, Ring: s.ring, MFA: s.mfa, Recovery: s.recovery, Throttle: s.throttle, Logger: s.log}
	s.mfa.TOTP = s.totp
	targets := map[principal.Action]stepup.TargetCheck{principal.ActionTOTPDelete: s.totp.OwnsTarget}
	if opt.passkeyTarget != nil {
		targets[principal.ActionPasskeyDelete] = opt.passkeyTarget
	}
	s.stepup = &stepup.Service{DB: s.db, Ring: s.ring, Sessions: sessionAssurance{s.sessions}, Accounts: mfaAccounts{s.accounts},
		Gates: gates, Passwords: passwordCheck{s.local, s.accounts}, TOTP: s.totp, Passkeys: opt.passkeys,
		Targets: targets, RecentWindow: cfg.StepUpMaxAge, Audit: authAudit, Logger: s.log}

	factors := []auth.Factor{totp.Factor{Service: s.totp}}
	if opt.passkeyFactor != nil {
		factors = append(factors, opt.passkeyFactor)
	}
	s.limiter = auth.NewLimiter()
	s.flow = &auth.Flow{DB: s.db, MAC: s.ring, Accounts: s.accounts, Sessions: s.sessions, Binding: httpapi.BrowserBinding,
		Password: s.local, Passwords: s.local, Factors: factors, Gates: gates, Settings: signInSettings{s.settings},
		Limiter: s.limiter, Audit: s.audit, Root: cfg.ApplicationRoot,
		Limits: auth.Limits{Enabled: cfg.RateLimits.Enabled, Login: auth.ParseRule(cfg.RateLimits.Login, ruleLogin),
			Default: auth.ParseRule(cfg.RateLimits.Default, ruleDefault)},
		Bootstrap: cfg.Accounts.BootstrapRegistrationEnabled, ClientAddr: httpapi.ClientAddr, Logger: s.log}

	var err error
	s.vault, err = vault.New(vault.Options{DB: s.db, Sealer: s.ring, StepUp: s.stepup,
		Limits: vault.Limits{MaxRecords: cfg.Stores.SSHKeyMaxRecords, MaxStoreBytes: int64(cfg.Stores.SSHKeyStoreMaxBytes)}})
	if err != nil {
		return fmt.Errorf("key vault: %w", err)
	}
	s.hosts = &hosts.Service{DB: s.db, Keys: s.vault, Persistent: opt.persistent, Limits: hosts.Limits{
		ProfileMaxRecords: cfg.Stores.ProfileMaxRecords, JumpHostMaxRecords: cfg.Stores.JumpHostMaxRecords,
		SOCKSProxyMaxRecords: cfg.Stores.SOCKSProxyMaxRecords, StoreMaxBytes: cfg.Stores.ConnectionStoreMaxBytes,
		ConfigMaxBytes: cfg.Stores.ConnectionConfigMaxBytes}}
	s.notes = &hostops.Notes{DB: s.db}
	s.hostkeys = hostkey.New(s.db, s.log)
	if s.policy, err = s.networkPolicy(); err != nil {
		return fmt.Errorf("network policy: %w", err)
	}
	var network client.Network = s.policy
	if in.network != nil {
		network = in.network(s.policy)
	}
	dialer := &client.Dialer{Net: network, HostKeys: s.hostkeys, Keys: s.vault, Logger: s.log}
	routes := terminal.SavedRoutes(s.hosts)
	if opt.terminalRoutes != nil {
		routes = opt.terminalRoutes
	}
	s.terminal, err = terminal.New(terminal.FromConfig(cfg.Terminal), terminal.Deps{
		Shells: legacyAlgorithmShells{dialer: dialer, settings: s.settings}, Profiles: s.hosts, Routes: routes, Log: s.log})
	if err != nil {
		return fmt.Errorf("terminal: %w", err)
	}
	s.closers = append(s.closers, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.terminal.Shutdown(ctx)
	})
	return nil
}

// networkPolicy is the outbound policy of SSH connections (ADR 0010).
// The tailnet rule reads the administrator setting on every decision.
func (s *system) networkPolicy() (*netpolicy.Policy, error) {
	n := s.cfg.Network
	return netpolicy.New(netpolicy.Config{
		BlockInternal: n.BlockInternalSSH, AllowedInternal: n.AllowedInternalNetworks,
		JumpRemoteDNS: n.ProxyJumpRemoteDNS, SOCKSRemoteDNS: n.SOCKSRemoteDNS,
		Tailnet: netpolicy.Tailnet{
			Restricted:          s.tailnetRestricted,
			Interface:           n.TailscaleInterface,
			FeatureEnabled:      n.TailscaleSSHEnabled,
			InterfaceConfigured: s.cfg.Explicit("TAILSCALE_SSH_INTERFACE"),
		},
		Logger: s.log,
	})
}

// tailnetRestricted is the setting tailscale_ssh_restrict_tailnet_routes;
// a failure to read it keeps the restriction (fail closed).
func (s *system) tailnetRestricted() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app, err := s.settings.App(ctx)
	if err != nil {
		s.log.Warn("tailnet setting unreadable; the restriction applies", "err", err)
		return true
	}
	return app.TailnetRouteRestricted
}

// registerHTTP adds the routes of every capability to the edge's mux.
func (s *system) registerHTTP(mux *http.ServeMux) {
	cfg := s.cfg
	limits := auth.FactorLimits{Limiter: s.limiter, Enabled: cfg.RateLimits.Enabled,
		Login: auth.ParseRule(cfg.RateLimits.Login, ruleLogin), Reauth: auth.ParseRule(cfg.RateLimits.Reauth, ruleReauth),
		ClientAddr: clientAddrString}
	authAudit := authAudit{s.audit}
	pending := s.flow.SignIn()
	s.flow.Register(mux)
	(&auth.FactorHTTP{MFA: s.mfa, Recovery: s.recovery, Throttle: s.throttle, StepUp: s.stepup, Pending: pending,
		Limits: limits, Root: cfg.ApplicationRoot, Audit: authAudit, Logger: s.log}).Register(mux)
	(&stepup.HTTP{Service: s.stepup, Limits: limits, Logger: s.log}).Register(mux)
	(&totp.HTTP{Service: s.totp, Gates: s.gates, StepUp: s.stepup, Pending: pending, Limits: limits, Audit: authAudit, Logger: s.log}).Register(mux)
	(&session.HTTP{Service: s.sessions, Audit: s.audit, Logger: s.log}).Register(mux)
	(&accounts.HTTP{Accounts: s.accounts, StepUp: s.stepup, Enabled: cfg.Accounts.AdminPanelEnabled, Logger: s.log}).Register(mux)
	(&operations.HTTP{Gates: s.gates, Inventory: securityInventory{db: s.db, accounts: s.accounts, totp: s.totp, passkeys: s.optional.passkeyList},
		StepUp: s.stepup, MAC: s.ring, Enabled: cfg.Accounts.AdminPanelEnabled, Logger: s.log}).Register(mux)
	(&settings.HTTP{Settings: s.settings, Gates: featureGates{s.gates}, Tour: tourDeployment(cfg, s.optional.tmux),
		BasePath: cfg.ApplicationRoot, Logger: s.log}).Register(mux)
	(&hosts.HTTP{Service: s.hosts, Logger: s.log}).Register(mux)
	(&hostops.OverviewHTTP{Inventory: overviewInventory{hosts: s.hosts, vault: s.vault}, Trust: hostTrust{s.hostkeys}, Logger: s.log}).Register(mux)
	(&hostkey.HTTP{Store: s.hostkeys, Targets: sshTargets{s.hosts}, StepUp: s.stepup, Enabled: cfg.Features.HostKeyManagement, Logger: s.log}).Register(mux)
	s.pages.register(mux)
	mux.Handle("GET /ws", s.realtime)
}

func clientAddrString(r *http.Request) string {
	if a := httpapi.ClientAddr(r); a.IsValid() {
		return a.String()
	}
	return ""
}
