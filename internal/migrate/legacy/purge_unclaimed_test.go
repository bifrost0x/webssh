package legacy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
)

// unclaimedFiles are files in DATA_DIR that are no 3.3 data: no step
// reads them and none reports them as kept in place.
var unclaimedFiles = []string{"certs/ldap-ca.pem", "users/user_3/notes-export.md", "users/user_3/profiles.json.bak"}

func migratedWithUnclaimed(t *testing.T) Options {
	t.Helper()
	dir := copyGolden(t)
	if err := os.RemoveAll(filepath.Join(dir, "deleted_users")); err != nil {
		t.Fatal(err)
	}
	for _, f := range unclaimedFiles {
		writeLegacyFile(t, dir, f, "operator data\n")
	}
	o := testOptions(t, dir)
	o.Registry = purgeRegistry(t)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	return o
}

// The purge names files that are no 3.3 data before the confirmation and
// puts them into the verified backup, as it does for paths the migration
// kept in place.
func TestPurgeBacksUpUnclaimedFiles(t *testing.T) {
	t.Parallel()
	o := migratedWithUnclaimed(t)
	var plan PurgePlan
	out, err := Purge(t.Context(), PurgeOptions{Options: o, BackupDir: t.TempDir(), Backup: backupWriter,
		Confirm: func(p PurgePlan) bool { plan = p; return true }})
	if err != nil {
		t.Fatal(err)
	}
	v, err := backup.Verify(t.Context(), out.Backup, probeTestKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range unclaimedFiles {
		if !slices.Contains(plan.Unclaimed, f) || !slices.Contains(plan.KeptFiles, f) {
			t.Errorf("plan does not name %s: %+v", f, plan)
		}
		if !slices.ContainsFunc(v.Manifest.Files, func(m backup.File) bool { return m.Name == "data/"+f }) {
			t.Errorf("backup lacks %s", f)
		}
	}
	for _, f := range plan.Unclaimed {
		if pythonDataFile(f) {
			t.Errorf("3.3 data file %s listed as unclaimed", f)
		}
	}
}

// Without a backup the unclaimed files would be lost: --skip-backup is
// refused and nothing is removed.
func TestPurgeUnclaimedNeedsBackup(t *testing.T) {
	t.Parallel()
	o := migratedWithUnclaimed(t)
	before := legacySnapshot(t, o.DataDir)
	if _, err := Purge(t.Context(), PurgeOptions{Options: o, SkipBackup: true}); stopCode(err) != CodePurgeRefused {
		t.Fatalf("skip-backup: %v", err)
	}
	assertUntouched(t, o.DataDir, before)
}

// In S5 the 3.3 data is gone, and files at recorded paths may have been
// written since the migration: a file whose size or hash differs from the
// record stays in place and is named in the plan.
func TestPurgeLegacyMissingKeepsChangedFiles(t *testing.T) {
	t.Parallel()
	o := migratedWithUnclaimed(t)
	for _, name := range append(legacyIndicators, "app.db") {
		_ = os.RemoveAll(filepath.Join(o.DataDir, name))
	}
	changed := filepath.Join(o.DataDir, "certs", "ldap-ca.pem")
	if err := os.WriteFile(changed, []byte("rewritten after the migration\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var plan PurgePlan
	out, err := Purge(t.Context(), PurgeOptions{Options: o, BackupDir: t.TempDir(), Backup: backupWriter,
		Confirm: func(p PurgePlan) bool { plan = p; return true }})
	if err != nil || out.State != S5 {
		t.Fatalf("%+v, %v", out, err)
	}
	if !slices.Contains(plan.Changed, "certs/ldap-ca.pem") || slices.Contains(plan.KeptFiles, "certs/ldap-ca.pem") {
		t.Fatalf("plan %+v", plan)
	}
	if got, err := os.ReadFile(changed); err != nil || string(got) != "rewritten after the migration\n" {
		t.Fatalf("changed file after the purge: %q, %v", got, err)
	}
	if st, err := startClosed(o); err != nil || st.State != S4 {
		t.Fatalf("%+v, %v", st, err)
	}
}

func TestPythonDataFile(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"app.db", "app.db-wal", "app_settings.json", "known_hosts", "session_epoch",
		"users/user_1/profiles.json", "users/user_12/keys/id_ed25519", "users/user_1/automation-vault.json"} {
		if !pythonDataFile(p) {
			t.Errorf("%s is 3.3 data", p)
		}
	}
	for _, p := range []string{"certs/ca.pem", "users/user_1/profiles.json.bak", "users/user_1/keys/a/b", "users/x/profiles.json",
		"users/user_/profiles.json", "users/user_1/notes.md", "notes.txt", "users/user_1",
		"users/user_1/keys/id.bak", "users/user_1/keys/id.tmp"} {
		if pythonDataFile(p) {
			t.Errorf("%s is no 3.3 data", p)
		}
	}
}
