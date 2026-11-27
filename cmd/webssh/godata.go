package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/buildinfo"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/platform"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

// loadConfig resolves DATA_DIR and SECRET_KEY like the entrypoint and
// reads the configuration.
func loadConfig() (config.Config, error) {
	read := func() (config.Config, error) {
		cfg, _, err := config.Bootstrap(os.LookupEnv, func(dir string) error {
			_, err := platform.PrepareDataDir(dir)
			return err
		})
		return cfg, err
	}
	cfg, err := read()
	if err != nil {
		return cfg, err
	}
	switch done, err := completeRotation(context.Background(), cfg); {
	case err != nil:
		return cfg, fmt.Errorf("complete the interrupted secret rotation: %w", err)
	case done:
		return read()
	}
	return cfg, nil
}

// migrationOptions are the options of the legacy migration for cfg; the
// server and the administrator commands use the same ones.
func migrationOptions(cfg config.Config, lookup config.LookupFunc) (legacy.Options, error) {
	reg, err := migrationRegistry(cfg, lookup)
	if err != nil {
		return legacy.Options{}, fmt.Errorf("migration registry: %w", err)
	}
	return legacy.Options{
		DataDir:         cfg.DataDir,
		Secret:          string(cfg.SecretKey.Bytes()),
		SecretSource:    string(cfg.SecretSource),
		BackupTempDir:   cfg.BackupTempDir,
		Release:         buildinfo.Read().Version,
		Registry:        reg,
		Origin:          legacyOrigin(cfg),
		RequireCoverage: true,
		BeforeStart:     activateRestore(cfg.DataDir, slog.Default()),
	}, nil
}

// requireCompleteRegistry refuses to activate a migration that would
// leave legacy entities neither migrated nor accounted for as pending.
func requireCompleteRegistry(r *legacy.Registry) error {
	if missing := r.Uncovered(); len(missing) > 0 {
		return fmt.Errorf("this build does not cover every legacy entity yet (%s); it does not activate a migration, "+
			"`webssh migrate --dry-run` still works", strings.Join(missing, ", "))
	}
	return nil
}

// goData is the Go database with the services the administrator commands
// use.
type goData struct {
	cfg      config.Config
	db       *store.DB
	ring     *keyring.Ring
	accounts *accounts.Service
	local    *local.Provider
	sessions *session.Service
	audit    *audit.Logger
	startup  *legacy.Startup
}

func (g *goData) Close() error {
	var errs []error
	if g.audit != nil {
		errs = append(errs, g.audit.Close())
	}
	switch {
	case g.db == nil:
	case g.startup == nil:
		// The running server owns the database (it holds the Go lock).
		errs = append(errs, g.db.CloseShared())
	default:
		errs = append(errs, g.db.Close())
	}
	if g.startup != nil {
		errs = append(errs, g.startup.Close())
	}
	return errors.Join(errs...)
}

// errNotMigrated refuses administrator commands before the first
// migration: they never migrate as a side effect.
var errNotMigrated = errors.New("the legacy data has not been migrated yet; start WebSSH once, which migrates it, " +
	"then repeat the command")

// openGoData opens the Go database for an administrator command. When no
// server runs, it runs the start-up state checks under the Go lock and
// holds the lock until Close; while a server runs (the lock is held), the
// server has checked the state and the command works on the same database,
// as the Python CLI worked beside the running application.
func openGoData(ctx context.Context, cfg config.Config) (*goData, error) {
	o, err := migrationOptions(cfg, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(cfg.DataDir, keyring.GoDirName, keyring.DatabaseName)
	_, dbErr := os.Lstat(dbPath)
	_, legacyErr := os.Lstat(filepath.Join(cfg.DataDir, "app.db"))
	if errors.Is(dbErr, fs.ErrNotExist) && legacyErr == nil {
		return nil, errNotMigrated
	}
	g := &goData{cfg: cfg}
	st, err := legacy.Start(ctx, o)
	var se *legacy.StopError
	switch {
	case errors.As(err, &se) && se.Code == legacy.CodeLocked:
		// A running server holds the lock.
	case err != nil:
		return nil, err
	default:
		g.startup = st
		if st.Migrated {
			return nil, errors.Join(errors.New("legacy: unexpected migration"), g.Close())
		}
	}
	if err := g.open(ctx, cfg, dbPath, errors.Is(dbErr, fs.ErrNotExist), legacyErr == nil); err != nil {
		return nil, errors.Join(err, g.Close())
	}
	return g, nil
}

func (g *goData) open(ctx context.Context, cfg config.Config, dbPath string, fresh, legacyPresent bool) error {
	// The material comes first: it is created only while no Go database
	// exists (a fresh installation).
	material, err := keyring.LoadOrCreateMaterial(cfg.DataDir, legacyPresent)
	if err != nil {
		return err
	}
	if g.ring, err = keyring.Open(cfg.SecretKey.Bytes(), material); err != nil {
		return err
	}
	if g.db, err = store.Open(ctx, dbPath, store.Options{}); err != nil {
		return err
	}
	if err := g.db.ApplyAll(ctx, schemas()...); err != nil {
		return err
	}
	if fresh {
		if err := legacy.RecordKeyID(ctx, g.db, g.ring.KeyID()); err != nil {
			return err
		}
	}
	if g.audit, err = audit.Open(filepath.Join(cfg.DataDir, keyring.LogsDirName),
		audit.Options{MaxBytes: cfg.Audit.LogMaxBytes, BackupCount: cfg.Audit.BackupCount}); err != nil {
		return err
	}
	hasher, err := local.NewHasher(local.DefaultParams, 1)
	if err != nil {
		return err
	}
	g.accounts = &accounts.Service{DB: g.db, Admins: cfg.Accounts.AdminUsers, Audit: g.audit}
	g.local = &local.Provider{DB: g.db, Accounts: g.accounts, Hasher: hasher}
	g.accounts.Credentials = g.local
	g.sessions = session.New(g.db, g.ring, g.accounts, nil)
	return nil
}
