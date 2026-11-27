package main

import (
	"bytes"
	json "encoding/json/v2"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/store"
)

// Python backups v1 and v2 restore on a new installation through the
// same migration as a DATA_DIR (spec 5.6, I-12): `webssh backup restore`
// with the build's complete registry leaves nothing pending, covers every
// entity as a step and the accounts sign in. data/go/ and data/logs/
// members of a Python archive never reach Go (I-18).
func TestBuildRestoresPythonBackupsThroughTheMigration(t *testing.T) {
	passwords := k10Passwords(t)
	cases := []struct {
		name, archive string
		recovery      bool
	}{
		{"export v2", filepath.Join(goldenBackups, "export.zip"), false},
		{"online v2", filepath.Join(goldenBackups, "online.zip"), false},
		{"recovery snapshot v2", filepath.Join(goldenBackups, "online-recovery-snapshot.zip"), true},
		{"v1 from 8c41517", filepath.Join(goldenLegacyDir, "backups", "backup-v1-8c41517.zip"), false},
		{"v2 with data/go", filepath.Join(goldenLegacyDir, "backups", "with-go-dir.zip"), false},
		{"v2 with data/logs", filepath.Join(goldenLegacyDir, "backups", "with-logs-members.zip"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := adminEnv(t)
			t.Setenv("SECRET_KEY", fixtureSecret(t))
			if code, out, e := runIn(t, "", "webssh", "backup", "verify", tc.archive); code != 0 {
				t.Fatalf("verify: %d %q %q", code, out, e)
			}
			argv := []string{"webssh", "backup", "restore", tc.archive, "--confirm-offline"}
			if tc.recovery {
				argv = append(argv, "--recovery-snapshot")
			}
			if code, out, e := runIn(t, "", argv...); code != 0 {
				t.Fatalf("restore: %d %q %q", code, out, e)
			}
			db, err := store.Open(t.Context(), filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			restoreReport(t, tc.archive, tc.recovery)
			signInMigrated(t, db, passwords)
		})
	}
}

// restoreReport restores archive with the build's complete registry, as
// `webssh backup restore` does, and checks its migration report: every
// entity ran as a step and nothing is pending.
func restoreReport(t *testing.T, archive string, recovery bool) {
	t.Helper()
	_, lookup := k10Env(t, t.TempDir())
	cfg, err := bootstrapConfig(lookup, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	o, err := migrationOptions(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.Open([]byte(goldenSecret(t)), bytes.Repeat([]byte{0x24}, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	rs := &legacy.Restorer{Options: o, Work: t.TempDir()}
	out, err := rs.RestoreLegacy(t.Context(), backup.LegacyRestore{Archive: f, Size: info.Size(), Staging: t.TempDir(),
		SecretKey: []byte(goldenSecret(t)), EnvironmentSecret: true, Ring: ring, RecoverySnapshot: recovery, RestoredAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	var rep legacy.Report
	if err := json.Unmarshal([]byte(out.Report), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Pending) != 0 {
		t.Fatalf("restore pending %+v", rep.Pending)
	}
	seen := map[string]bool{}
	for _, e := range rep.Entities {
		seen[e.Entity] = true
	}
	for _, e := range legacy.Entities {
		if !seen[e] {
			t.Errorf("%s missing from the restore report", e)
		}
	}
}
