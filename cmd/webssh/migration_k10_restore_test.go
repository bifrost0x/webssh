package main

import (
	"bytes"
	json "encoding/json/v2"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		// SECRET_KEY from the environment wins over an outdated
		// data/secret_key, as at Python's next start (5.6 step 4).
		{"v2 with an outdated data/secret_key", filepath.Join(goldenLegacyDir, "backups", "outdated-secret-key.zip"), false},
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
			keptRestoreReport(t, dir)
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

// keptRestoreReport checks that the restore kept the migration report of
// the archive in the Go directory (MG1-2, migration-spec 5.6): one file,
// owner-only, every entity a step.
func keptRestoreReport(t *testing.T, dir string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, keyring.GoDirName, "restore-report-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("restore reports %v, %v", files, err)
	}
	info, err := os.Stat(files[0])
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("restore report %v, %v", info, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var rep legacy.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Result != legacy.ResultCompleted || len(rep.Entities) != len(legacy.Entities) || len(rep.Pending) != 0 {
		t.Fatalf("restore report: result %s, %d entities, pending %v", rep.Result, len(rep.Entities), rep.Pending)
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

// Without SECRET_KEY in the environment the archive's outdated
// data/secret_key is the legacy key; it does not decrypt the records, so
// the restore stops before anything is activated (D-08) and the
// installation keeps its database.
func TestBuildRefusesAPythonBackupWithAnOutdatedSecret(t *testing.T) {
	dir := adminEnv(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret_key"), []byte(fixtureSecret(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("SECRET_KEY")
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatalf("create-admin: %s", e)
	}
	before := storedUsernames(t)
	archive := filepath.Join(goldenLegacyDir, "backups", "outdated-secret-key.zip")
	code, out, e := runIn(t, "", "webssh", "backup", "restore", archive, "--confirm-offline")
	if code == 0 {
		t.Fatalf("restore with the outdated archive secret succeeded: %q", out)
	}
	if !strings.Contains(e, "secret_key_mismatch") && !strings.Contains(e, "SECRET_KEY") {
		t.Errorf("restore error %q", e)
	}
	if after := storedUsernames(t); !slices.Equal(after, before) {
		t.Errorf("accounts changed: %v, was %v", after, before)
	}
}
