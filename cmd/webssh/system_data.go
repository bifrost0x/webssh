package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/platform"
	"github.com/bifrost0x/webssh/internal/realtime"
	"github.com/bifrost0x/webssh/internal/store"
)

// bootstrapConfig resolves the configuration in the order of config.Bootstrap:
// DATA_DIR, the prepared data directory, SECRET_KEY, then everything
// else. The warnings go to the start-up log.
func bootstrapConfig(lookup config.LookupFunc, log *slog.Logger) (config.Config, error) {
	cfg, warnings, err := config.Bootstrap(lookup, func(dir string) error {
		_, err := platform.PrepareDataDir(dir)
		return err
	})
	if err != nil {
		return config.Config{}, err
	}
	for _, w := range warnings {
		log.Warn("configuration", "kind", string(w.Kind), "variable", w.Variable, "message", w.Message)
	}
	if desc, err := platform.DescribeDataDir(cfg.DataDir); err == nil {
		log.Info("data directory", "path", cfg.DataDir, "access", desc)
	}
	return cfg, nil
}

// legacyOrigin evaluates the realtime origin rule of the Python
// configuration (K6 A1, D-01) for the migration record.
func legacyOrigin(cfg config.Config) legacy.OriginRule {
	cidrs := prefixStrings(cfg.Proxies.CIDRs)
	keep := keepLegacyScheme(cfg)
	evidence := fmt.Sprintf("CORS_ORIGINS=%s SOCKETIO_ALLOW_ANY_ORIGIN=%t TRUSTED_PROXIES=%d TRUSTED_PROXY_CIDRS=%s",
		corsLabel(cfg), cfg.Origins.SkipSameOrigin, cfg.Proxies.Hops, strings.Join(cidrs, ","))
	return legacy.OriginRule{KeepLegacyScheme: keep, Evidence: evidence}
}

// keepLegacyScheme is realtime.KeepLegacySchemeRule for cfg.
func keepLegacyScheme(cfg config.Config) bool {
	return realtime.KeepLegacySchemeRule(cfg.Origins.AllowAny, cfg.Origins.SkipSameOrigin, cfg.Proxies.Hops, prefixStrings(cfg.Proxies.CIDRs))
}

func corsLabel(cfg config.Config) string {
	if cfg.Origins.AllowAny {
		return "*"
	}
	return strconv.Itoa(len(cfg.Origins.List)) + " origins"
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// startMigration runs the start-up state machine of the migration
// specification (section 5.1). It holds the Go lock until the returned
// Startup is closed. A state that must not start is a *legacy.StopError.
func startMigration(ctx context.Context, cfg config.Config, lookup config.LookupFunc, log *slog.Logger) (*legacy.Startup, error) {
	o, err := migrationOptions(cfg, lookup)
	if err != nil {
		return nil, err
	}
	st, err := legacy.Start(ctx, o)
	if err != nil {
		if stop, ok := errors.AsType[*legacy.StopError](err); ok {
			log.Error("migration stop", "state", string(stop.State), "code", stop.Code, "entity", stop.Entity,
				"user_id", stop.UserID, "record", stop.Record, "message", stop.Message)
		}
		return nil, fmt.Errorf("start-up check: %w", err)
	}
	log.Info("data state", "state", string(st.State), "migrated", st.Migrated)
	if st.Migrated {
		log.Info("migration completed", "report", st.ReportPath)
		if r := st.Report; r != nil {
			for _, p := range r.Pending {
				log.Info("kept in place until a later release", "pending", fmt.Sprintf("%+v", p))
			}
		}
	}
	for _, w := range st.Warnings {
		log.Warn("migration", "code", w.Code, "user_id", w.UserID, "count", w.Count, "message", w.Message)
	}
	return st, nil
}

// openStore opens the Go database, applies every schema of this build and
// binds the keyring to it: a database without a key identifier (a new
// installation) records the ring's, any other must match it (state S9).
func openStore(ctx context.Context, cfg config.Config, st *legacy.Startup) (*store.DB, *keyring.Ring, error) {
	material, err := keyring.LoadOrCreateMaterial(cfg.DataDir, st.State != legacy.S0)
	if err != nil {
		return nil, nil, fmt.Errorf("keyring material: %w", err)
	}
	ring, err := keyring.Open(cfg.SecretKey.Bytes(), material)
	clear(material)
	if err != nil {
		return nil, nil, fmt.Errorf("keyring: %w", err)
	}
	db, err := store.Open(ctx, filepath.Join(cfg.DataDir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	fail := func(err error) (*store.DB, *keyring.Ring, error) {
		return nil, nil, errors.Join(err, db.Close())
	}
	if err := db.ApplyAll(ctx, schemas()...); err != nil {
		return fail(fmt.Errorf("apply schemas: %w", err))
	}
	stored, err := legacy.StoredKeyID(ctx, db)
	if err != nil {
		return fail(fmt.Errorf("read key identifier: %w", err))
	}
	if stored == "" {
		if err := legacy.RecordKeyID(ctx, db, ring.KeyID()); err != nil {
			return fail(fmt.Errorf("record key identifier: %w", err))
		}
	} else if err := ring.Verify(stored); err != nil {
		return fail(fmt.Errorf("keyring does not match the database: %w", err))
	}
	return db, ring, nil
}

// schemas are the store schemas of this build: the migration record, the
// capabilities and every registered extension. A schema appears once.
func schemas() []store.Schema {
	out := append([]store.Schema{legacy.RecordSchema()}, capabilitySchemas()...)
	for _, e := range extensions {
		for _, s := range e.schemas {
			if !slices.ContainsFunc(out, func(o store.Schema) bool { return o.Owner == s.Owner }) {
				out = append(out, s)
			}
		}
	}
	return out
}
