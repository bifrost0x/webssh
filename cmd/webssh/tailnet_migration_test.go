package main

import (
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// D-28 under D-01, functionally: after the migration of a Python data
// directory the tailnet rule follows the Tailscale SSH switch as before,
// so an ordinary connection to a tailnet node still opens while the switch
// is off and the interface exists, and the start reports the gap. A new
// installation refuses the same connection.
func TestMigratedInstallationKeepsTheTailnetBehaviour(t *testing.T) {
	node := netip.MustParseAddr("100.100.100.10")
	routes := func(_ context.Context, addr netip.Addr) (netpolicy.Route, error) {
		return netpolicy.Route{Interface: "tailscale0", Table: 52}, nil
	}
	policyFor := func(t *testing.T, dataDir string, migrate bool) *netpolicy.Policy {
		t.Helper()
		env := map[string]string{"DATA_DIR": dataDir, "SECRET_KEY": goldenSecret(t), "BACKUP_TEMP_DIR": t.TempDir()}
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
		s := &system{cfg: cfg, log: log, settings: settings.New(db, settingsEnvironment(cfg, lookup))}
		p, err := netpolicy.New(netpolicy.Config{Tailnet: netpolicy.Tailnet{
			Restricted: s.tailnetRestricted, Interface: "tailscale0", FollowsSwitch: s.tailnetFollowsSwitch,
			Lookup: routes, InterfacePresent: func(string) bool { return true },
		}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	migrated := policyFor(t, extractGolden(t, "datadir-extended.tar"), true)
	if _, err := migrated.Admit(t.Context(), netpolicy.RoleSSH, node.String(), 22); err != nil {
		t.Fatalf("upgraded installation refuses the tailnet node it reached before: %v", err)
	}
	if !migrated.TailnetLegacyGap() {
		t.Fatal("the administrator is not warned about the open tailnet")
	}

	fresh := policyFor(t, t.TempDir(), false)
	if _, err := fresh.Admit(t.Context(), netpolicy.RoleSSH, node.String(), 22); err == nil {
		t.Fatal("a new installation reaches a tailnet node with ordinary SSH")
	}
	if fresh.TailnetLegacyGap() {
		t.Fatal("a new installation reports the legacy gap")
	}
}
