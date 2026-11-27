package main

import (
	"log/slog"
	"maps"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// A13 under D-01, functionally: after the migration of a Python data
// directory an ordinary account may still start host discovery and the
// reachability check, as every signed-in account could before. A new
// installation grants both to administrators only. HOST_DISCOVERY_ENABLED
// stays the ceiling either way.
func TestMigratedInstallationKeepsDiscoveryForEveryAccount(t *testing.T) {
	wiringFor := func(t *testing.T, dataDir string, migrate bool, extra map[string]string) *discoveryWiring {
		t.Helper()
		env := map[string]string{"DATA_DIR": dataDir, "SECRET_KEY": goldenSecret(t), "BACKUP_TEMP_DIR": t.TempDir()}
		maps.Copy(env, extra)
		lookup := func(name string) (string, bool) { v, ok := env[name]; return v, ok }
		log := slog.New(slog.DiscardHandler)
		cfg, err := bootstrapConfig(lookup, log)
		if err != nil {
			t.Fatal(err)
		}
		st, err := startMigration(t.Context(), cfg, lookup, log)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		if st.Migrated != migrate {
			t.Fatalf("state %s, migrated %v", st.State, st.Migrated)
		}
		db, err := store.Open(t.Context(), filepath.Join(dataDir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if !migrate {
			sc := settings.Schema()
			if err := db.Apply(t.Context(), sc.Owner, sc.Migrations); err != nil {
				t.Fatal(err)
			}
		}
		return &discoveryWiring{sys: &system{cfg: cfg, log: log, settings: settings.New(db, settingsEnvironment(cfg, lookup))}}
	}
	user := principal.Principal{UserID: 7, SessionID: "s"}
	admin := principal.Principal{UserID: 1, SessionID: "a", IsAdmin: true}
	check := func(t *testing.T, w *discoveryWiring, p principal.Principal, key string, want bool) {
		t.Helper()
		ok, err := w.permitted(key)(t.Context(), p)
		if err != nil || ok != want {
			t.Errorf("%s for admin=%v: %v %v, want %v", key, p.IsAdmin, ok, err, want)
		}
	}

	migrated := wiringFor(t, extractGolden(t, "datadir-extended.tar"), true, nil)
	for _, key := range []string{settings.PolicyDiscovery, settings.PolicyReachability} {
		check(t, migrated, user, key, true)
		check(t, migrated, admin, key, true)
	}
	if !migrated.discoveryAvailable(t.Context(), user) {
		t.Error("the upgraded installation hides discovery from an ordinary account")
	}

	fresh := wiringFor(t, t.TempDir(), false, nil)
	for _, key := range []string{settings.PolicyDiscovery, settings.PolicyReachability} {
		check(t, fresh, user, key, false)
		check(t, fresh, admin, key, true)
	}
	if fresh.discoveryAvailable(t.Context(), user) || !fresh.discoveryAvailable(t.Context(), admin) {
		t.Error("a new installation offers discovery to the wrong accounts")
	}

	off := wiringFor(t, t.TempDir(), false, map[string]string{"HOST_DISCOVERY_ENABLED": "false"})
	if off.discoveryAvailable(t.Context(), admin) {
		t.Error("HOST_DISCOVERY_ENABLED=false does not end discovery for administrators")
	}
}
