package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
	"github.com/bifrost0x/webssh/internal/vault"
)

// bootInput is what a start of the server gets from its caller.
type bootInput struct {
	lookup config.LookupFunc
	log    *slog.Logger
	// console receives the copy of the audit log; nil writes none.
	console io.Writer
	// stopping reports that the shutdown began (readiness).
	stopping func() bool
	// fastHashing selects cheap password hashing (end-to-end suite only).
	fastHashing bool
	// network replaces the outbound dialer of the SSH client (end-to-end
	// suite only); nil uses the network policy.
	network func(*netpolicy.Policy) client.Network
}

// optional holds the dependencies that capabilities built in parallel
// provide through an extension's prepare hook. Nil means: not in this
// build, and every consumer handles that.
type optional struct {
	passkeys       stepup.Passkeys
	passkeyFactor  auth.Factor
	passkeyCount   auth.DurableFactor
	passkeyTarget  stepup.TargetCheck
	passkeyList    func(ctx context.Context, userID int64) ([]operations.Credential, error)
	persistent     hosts.PersistentSessions
	featureReady   map[string]operations.Readiness
	terminalRoutes terminal.SavedRoutes
	// ldapStepUp offers the LDAP step-up proof; sessionGate runs before
	// every authenticated request and realtime connection (LDAP
	// revalidation). Both come from the area "ldap".
	ldapStepUp  stepup.Directory
	sessionGate func(ctx context.Context, p principal.Principal) error
	// passkeyPlaceholder stores a passkey that never authenticates (end-to-
	// end seed only).
	//lint:ignore U1000 read by the end-to-end build (e2e.go)
	passkeyPlaceholder func(ctx context.Context, userID int64, name, credentialID string, transports []string) error
}

// system is the wired server: the data directory, the store, the keyring
// and every capability of this build.
type system struct {
	cfg      config.Config
	log      *slog.Logger
	startup  *legacy.Startup
	db       *store.DB
	ring     *keyring.Ring
	audit    *audit.Logger
	optional optional

	maintenance atomic.Bool

	accounts *accounts.Service
	local    *local.Provider
	sessions *session.Service
	settings *settings.Service
	gates    *operations.Gates
	mfa      *auth.MFA
	recovery *auth.Recovery
	throttle *auth.Throttle
	totp     *totp.Service
	stepup   *stepup.Service
	flow     *auth.Flow
	limiter  *auth.Limiter
	vault    *vault.Service
	hosts    *hosts.Service
	notes    *hostops.Notes
	hostkeys *hostkey.Store
	policy   *netpolicy.Policy
	terminal *terminal.Manager
	realtime *realtime.Server
	edge     *httpapi.Handler
	pages    *pages

	background     sync.WaitGroup
	stopBackground context.CancelFunc
	closers        []func() error
}

// openSystem starts WebSSH on its data directory: configuration, the
// migration state machine, store and keyring, then every capability. On
// failure everything opened so far is closed again.
func openSystem(ctx context.Context, in bootInput) (sys *system, err error) {
	cfg, err := bootstrapConfig(in.lookup, in.log)
	if err != nil {
		return nil, err
	}
	sys = &system{cfg: cfg, log: in.log}
	defer func() {
		if err != nil {
			err = errors.Join(err, sys.close())
			sys = nil
		}
	}()
	if sys.startup, err = startMigration(ctx, cfg, in.lookup, in.log); err != nil {
		return sys, err
	}
	sys.closers = append(sys.closers, sys.startup.Close)
	if sys.db, sys.ring, err = openStore(ctx, cfg, sys.startup); err != nil {
		return sys, err
	}
	sys.closers = append(sys.closers, sys.db.Close)
	if sys.audit, err = audit.Open(filepath.Join(cfg.DataDir, keyring.LogsDirName),
		audit.Options{MaxBytes: cfg.Audit.LogMaxBytes, BackupCount: cfg.Audit.BackupCount, Console: in.console}); err != nil {
		return sys, fmt.Errorf("audit log: %w", err)
	}
	sys.closers = append(sys.closers, sys.audit.Close)
	auditMigration(sys.audit, sys.startup)
	if err := sys.buildCore(ctx, in); err != nil {
		return sys, err
	}
	for _, e := range extensions {
		if e.prepare != nil {
			if err := e.prepare(sys); err != nil {
				return sys, fmt.Errorf("extension %s: %w", e.name, err)
			}
		}
	}
	if err := sys.buildCapabilities(in); err != nil {
		return sys, err
	}
	if err := sys.buildEdges(in); err != nil {
		return sys, err
	}
	sys.startBackground(ctx)
	return sys, nil
}

// buildCore wires the accounts, sessions and settings that everything
// else depends on, and applies the start-up rules of the accounts.
func (s *system) buildCore(ctx context.Context, in bootInput) error {
	cfg := s.cfg
	params := local.DefaultParams
	if in.fastHashing {
		params = local.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	}
	hasher, err := local.NewHasher(params, 0)
	if err != nil {
		return fmt.Errorf("password hasher: %w", err)
	}
	s.accounts = &accounts.Service{DB: s.db, Admins: accounts.Admins(cfg.Accounts.AdminUsers), Audit: s.audit, Logger: s.log}
	s.local = &local.Provider{DB: s.db, Accounts: s.accounts, Hasher: hasher, Logger: s.log}
	s.accounts.Credentials = s.local
	s.settings = settings.New(s.db, settingsEnvironment(cfg, in.lookup))
	s.sessions = session.New(s.db, s.ring, s.accounts, sessionDurations{s.settings})
	// The first call notes the journal position; later revocations of
	// other processes are followed from here on (background.go).
	if _, err := s.sessions.FollowRevocations(ctx); err != nil {
		return fmt.Errorf("session revocation journal: %w", err)
	}
	if err := s.accounts.Normalize(ctx); err != nil {
		return fmt.Errorf("account start-up rules: %w", err)
	}
	app, err := s.settings.App(ctx)
	if err != nil {
		return fmt.Errorf("application settings: %w", err)
	}
	if err := s.audit.SetBackupCount(app.AuditBackupCount); err != nil {
		s.log.Warn("audit log backup count not applied", "err", err)
	}
	for _, m := range app.MaterialisedSettings() {
		s.log.Info("setting carried over from the previous release", "setting", m.Setting, "value", m.Value, "rule", m.Rule)
	}
	s.optional.featureReady = featureReadiness()
	return nil
}

// close releases everything in reverse order of opening; the Go lock is
// released last. It is safe to call on a partly opened system.
func (s *system) close() error {
	if s.stopBackground != nil {
		s.stopBackground()
		s.background.Wait()
	}
	var errs []error
	for _, v := range slices.Backward(s.closers) {
		errs = append(errs, v())
	}
	s.closers = nil
	return errors.Join(errs...)
}

// drain ends the long-lived work at shutdown: the realtime connections
// first (close code 4503), then the terminal sessions.
func (s *system) drain(ctx context.Context) error {
	var errs []error
	if s.realtime != nil {
		errs = append(errs, s.realtime.Shutdown(ctx))
	}
	if s.terminal != nil {
		errs = append(errs, s.terminal.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

// shutdownGrace is RUNTIME_SHUTDOWN_GRACE_SECONDS, or the default.
func (s *system) shutdownGrace() time.Duration {
	if s.cfg.ShutdownGrace > 0 {
		return s.cfg.ShutdownGrace
	}
	return shutdownGrace
}
