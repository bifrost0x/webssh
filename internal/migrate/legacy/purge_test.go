package legacy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// purgeRegistry is testRegistry without the entity kept in place, so that
// the record has no pending data and a purge is allowed.
func purgeRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	r.Schemas(testSchema)
	for _, err := range []error{
		AddSingleUserStores(r),
		r.Add(GroupKeys, func() Step { return &testKeysStep{} }),
		r.Add(GroupTerminal, func() Step { return &testSessionsStep{} }),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// migratedForPurge returns options for a golden data directory migrated
// without pending entities.
func migratedForPurge(t *testing.T) Options {
	t.Helper()
	o := testOptions(t, copyGolden(t))
	o.Registry = purgeRegistry(t)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	return o
}

// probeTestKey opens one sealed key of the test step, as vault.ProbeSealed
// does for the vault.
func probeTestKey(ctx context.Context, tx *store.Tx, ring *keyring.Ring) (bool, error) {
	var id string
	var sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT id, sealed FROM hostops_c7_keys ORDER BY id LIMIT 1`).Scan(&id, &sealed); err != nil {
		return false, err
	}
	_, err := ring.Open(keyring.SSHKey, keyAAD(id), sealed)
	return true, err
}

func backupWriter(ctx context.Context, req BackupRequest) (string, error) {
	path, err := backup.Write(req.Dir, backup.Contents{Database: req.Database, SecretKey: req.Secret, Material: req.Material,
		KeyID: req.KeyID, Release: req.Release, Reason: "legacy-purge", Now: req.Now})
	if err != nil {
		return "", err
	}
	v, err := backup.Verify(ctx, path, probeTestKey)
	if err == nil && !v.SealedChecked {
		err = errors.New("no sealed record checked")
	}
	return path, err
}

func TestPurge(t *testing.T) {
	t.Parallel()
	o := migratedForPurge(t)
	l := mustLayout(t, o.DataDir)
	// A directory --replace set aside under logs/.webssh-go/ moves into go/.
	aside := filepath.Join(l.stateDir, "replaced-20261126T000000.000000000Z")
	if err := os.MkdirAll(aside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aside, "keyring-material-logs"), []byte("old material"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	out, err := Purge(t.Context(), PurgeOptions{Options: o, BackupDir: dest, Backup: backupWriter})
	if err != nil {
		t.Fatal(err)
	}
	if out.State != S2 || out.Removed == 0 || filepath.Dir(out.Backup) != dest {
		t.Fatalf("%+v", out)
	}
	if _, err := backup.Verify(t.Context(), out.Backup, probeTestKey); err != nil {
		t.Fatalf("backup: %v", err)
	}
	for _, name := range append(legacyIndicators, "app.db") {
		if found, err := holdsData(filepath.Join(o.DataDir, name)); err != nil || found {
			t.Errorf("%s still holds data (%v)", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(o.DataDir, "secret_key")); err != nil {
		t.Errorf("secret_key was removed: %v", err)
	}
	if _, err := os.Lstat(l.stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("logs/.webssh-go/ still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(l.goDir, keyring.MaterialName)); err != nil {
		t.Errorf("material not in go/: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(l.goDir, filepath.Base(aside), "keyring-material-logs")); err != nil || string(b) != "old material" {
		t.Errorf("set-aside material not moved: %q, %v", b, err)
	}
	st, err := startClosed(o)
	if err != nil || st.State != S4 {
		t.Fatalf("start after purge: %+v, %v", st, err)
	}
	db, err := store.Open(t.Context(), l.database, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var inGo int
	err = db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT material_in_go FROM migrate_keyring`).Scan(&inGo)
	})
	if err := errors.Join(err, db.CloseForActivation(t.Context())); err != nil || inGo != 1 {
		t.Errorf("material_in_go = %d, %v", inGo, err)
	}
	// A second purge only reports the state; a new legacy source after the
	// purge stops the start.
	if again, err := Purge(t.Context(), PurgeOptions{Options: o, SkipBackup: true}); err != nil || again.State != S4 {
		t.Errorf("second purge: %+v, %v", again, err)
	}
	if err := os.WriteFile(filepath.Join(o.DataDir, "app.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := startClosed(o); stopCode(err) != CodeLegacyAfterPurge {
		t.Errorf("legacy after purge: %v", err)
	}
}

// Legacy data kept for a later release is never purged.
func TestPurgeRefusesPending(t *testing.T) {
	t.Parallel()
	o := testOptions(t, copyGolden(t))
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	before := legacySnapshot(t, o.DataDir)
	dest := t.TempDir()
	_, err := Purge(t.Context(), PurgeOptions{Options: o, BackupDir: dest, Backup: backupWriter})
	if stopCode(err) != CodePurgeRefused {
		t.Fatalf("got %v", err)
	}
	assertUntouched(t, o.DataDir, before)
	if entries, _ := os.ReadDir(dest); len(entries) != 0 {
		t.Errorf("a backup was written: %v", entries)
	}
}

// Without a verified backup nothing is removed: a failing writer, an
// unwritable target and a target in go/ all abort (section 8.3).
func TestPurgeBackupFailures(t *testing.T) {
	t.Parallel()
	failing := func(context.Context, BackupRequest) (string, error) { return "", errors.New("disk full") }
	for name, mod := range map[string]func(o *PurgeOptions){
		"writer fails":  func(o *PurgeOptions) { o.BackupDir, o.Backup = t.TempDir(), failing },
		"missing dir":   func(o *PurgeOptions) { o.BackupDir = filepath.Join(t.TempDir(), "none") },
		"inside go/":    func(o *PurgeOptions) { o.BackupDir = filepath.Join(o.DataDir, "go") },
		"read-only dir": func(o *PurgeOptions) { o.BackupDir = readOnlyDir(t) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			po := PurgeOptions{Options: migratedForPurge(t), Backup: backupWriter}
			mod(&po)
			before := legacySnapshot(t, po.DataDir)
			if _, err := Purge(t.Context(), po); stopCode(err) != CodePurgeBackup {
				t.Fatalf("got %v", err)
			}
			assertUntouched(t, po.DataDir, before)
			if st, err := startClosed(po.Options); err != nil || st.State != S2 {
				t.Errorf("after the refusal: %+v, %v", st, err)
			}
		})
	}
}

func readOnlyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		_ = f.Close()
		t.Skip("running with permissions that ignore directory modes")
	}
	return dir
}

// In S5 the purge records its entry; nothing is left to remove.
func TestPurgeLegacyMissing(t *testing.T) {
	t.Parallel()
	o := migratedForPurge(t)
	for _, name := range append(legacyIndicators, "app.db") {
		_ = os.RemoveAll(filepath.Join(o.DataDir, name))
	}
	out, err := Purge(t.Context(), PurgeOptions{Options: o, BackupDir: t.TempDir(), Backup: backupWriter})
	if err != nil || out.State != S5 {
		t.Fatalf("%+v, %v", out, err)
	}
	if st, err := startClosed(o); err != nil || st.State != S4 || len(st.Warnings) != 0 {
		t.Fatalf("%+v, %v", st, err)
	}
}

// A Go-native installation has nothing to purge.
func TestPurgeWithoutMigration(t *testing.T) {
	t.Parallel()
	o := testOptions(t, t.TempDir())
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	if _, err := Purge(t.Context(), PurgeOptions{Options: o, SkipBackup: true}); stopCode(err) != CodePurgeRefused {
		t.Fatalf("got %v", err)
	}
}

func TestPurgeList(t *testing.T) {
	t.Parallel()
	got := purgeList([]FileStat{{Path: "app.db"}, {Path: "secret_key"}, {Path: "users/user_1/profiles.json"},
		{Path: "go/webssh.db"}, {Path: "logs/x.log"}, {Path: "../escape"}, {Path: "/abs"}})
	want := []string{"app.db", "users/user_1/profiles.json"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("purgeList = %q, want %q", got, want)
	}
}

// removeLegacyFiles never follows a link out of the data directory.
func TestRemoveLegacyFilesStaysInside(t *testing.T) {
	t.Parallel()
	dataDir, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dataDir, "users")); err != nil {
		t.Fatal(err)
	}
	if err := removeLegacyFiles(dataDir, []string{"users/victim"}, Options{}); err == nil {
		t.Error("a path through a link was accepted")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("the file outside was removed: %v", err)
	}
	if err := removeLegacyFiles(dataDir, []string{"../victim"}, Options{}); err == nil {
		t.Error("a path outside was accepted")
	}
}
