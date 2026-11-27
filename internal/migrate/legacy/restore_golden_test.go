package legacy

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// restoreRegistry holds every migration step this package has, as the
// one-time migration of the build runs them.
func restoreRegistry(t *testing.T) *Registry {
	t.Helper()
	r := m1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
	if err := errors.Join(AddCredentials(r), AddSMB(r), AddLDAP(r), AddOIDCIdentities(r), AddBackupState(r, ""),
		AddCommands(r), AddAutomation(r), AddSchedules(r)); err != nil {
		t.Fatal(err)
	}
	return r
}

var restoredAt = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

// restoreGolden restores a Python archive through RestoreLegacy into a
// new database sealed with a fresh keyring, as the restore of a running
// installation does.
func restoreGolden(t *testing.T, archive string, recovery bool) migrated {
	t.Helper()
	material := bytes.Repeat([]byte{0x42}, keyring.MaterialSize)
	ring, err := keyring.Open([]byte(golden.manifest.SecretKey.Value), material)
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
	rs := &Restorer{Options: Options{Registry: restoreRegistry(t), Release: "test", RequireCoverage: true,
		Now: func() time.Time { return restoredAt }}, Work: t.TempDir()}
	out, err := rs.RestoreLegacy(t.Context(), backup.LegacyRestore{Archive: f, Size: info.Size(), Staging: t.TempDir(),
		SecretKey: []byte("the active secret of the new installation"), Ring: ring, RecoverySnapshot: recovery, RestoredAt: restoredAt})
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal([]byte(out.Report), &rep); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), out.Database, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return migrated{db: db, ring: ring, report: &rep}
}

func countIn(t *testing.T, db *store.DB, table string) int {
	t.Helper()
	var n int
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// formatOne derives a format 1 archive (the oldest Python release) from
// a golden format 2 archive, as TestBackupFormatOne does.
func formatOne(t *testing.T, name string) string {
	t.Helper()
	return rewriteArchive(t, backupPath(name), func(m map[string]any, _ map[string][]byte) {
		m["format_version"] = 1
		delete(m, "created_at")
		delete(m, "data_schema_version")
		delete(m, "producer")
	})
}

// Python backups v1 and v2 of the golden data set go through the steps of
// the first migration, and every entity is verified functionally on the
// restored database: accounts sign in, factors work, hosts and settings
// equal the legacy records, and an export restores without remote
// credentials (with the recovery check notice), a recovery snapshot with
// them. The secret of the archive (data/secret_key) decrypts the legacy
// records; the restored secrets are sealed with the active keyring.
func TestRestorePythonBackupsGolden(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		archive  func(t *testing.T) string
		recovery bool
		kind     backup.ArchiveKind
	}{
		{"export v2", func(*testing.T) string { return backupPath("export") }, false, backup.KindPythonV2},
		{"online v2", func(*testing.T) string { return backupPath("online") }, false, backup.KindPythonV2},
		{"recovery snapshot v2", func(*testing.T) string { return backupPath("recovery_snapshot") }, true, backup.KindPythonV2},
		{"export v1", func(t *testing.T) string { return formatOne(t, "export") }, false, backup.KindPythonV1},
		{"recovery snapshot v1", func(t *testing.T) string { return formatOne(t, "recovery_snapshot") }, true, backup.KindPythonV1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := restoreGolden(t, tc.archive(t), tc.recovery)
			covered := map[string]bool{}
			for _, e := range m.report.Entities {
				covered[e.Entity] = true
			}
			for _, p := range m.report.Pending {
				covered[p.Entity] = true
			}
			if len(covered) != len(Entities) {
				t.Fatalf("the restore covers %d of %d entities", len(covered), len(Entities))
			}
			// Python's restore raises every account's generation once
			// (restore_sanitizer.py), which invalidates schedule approvals.
			checkGoldenAccounts(t, m, 1)
			checkGoldenFactors(t, m)
			checkGoldenHosts(t, m, golden.dataDir)
			checkGoldenHostTrust(t, m, golden.dataDir)
			// A01: persistent tmux sessions are not restored.
			if e := m.entity(t, "A01"); e.Written != 0 {
				t.Errorf("persistent sessions restored: %+v", e)
			}
			notice := countIn(t, m.db, `settings_app WHERE key = 'recovery_check'`)
			if tc.recovery {
				checkGoldenKeys(t, m)
				checkRestoredCredentials(t, m)
				if notice != 0 {
					t.Error("a recovery snapshot set the recovery check notice")
				}
				return
			}
			for _, table := range []string{"vault_ssh_keys", "vault_credentials", "vault_legacy_automation"} {
				if n := countIn(t, m.db, table); n != 0 {
					t.Errorf("an export restored %d rows of %s", n, table)
				}
			}
			if notice != 1 {
				t.Error("the export restore did not set the recovery check notice")
			}
		})
	}
}

func checkRestoredCredentials(t *testing.T, m migrated) {
	t.Helper()
	owner := goldenUserByName(t, "local_user").ID
	want := golden.manifest.Values.NamedCredential
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		got, _, _, err := vault.ExportCredentialsTx(t.Context(), tx, m.ring, owner)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(got, func(c vault.ExportedCredential) bool { return c.ID == want.RecordID })
		if i < 0 || string(got[i].Password) != want.Password {
			t.Errorf("the restored credential %s does not open with the active keyring", want.RecordID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The 16 malicious or damaged archives of K3 are refused by the restore
// before anything is extracted.
func TestRestoreRefusesK3Archives(t *testing.T) {
	t.Parallel()
	ring, err := keyring.Open([]byte("s"), bytes.Repeat([]byte{1}, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	cases := backupRejectionCases()
	if len(cases) != 16 {
		t.Fatalf("%d K3 cases", len(cases))
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archive := craftRejection(t, tt)
			raw, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			staging := t.TempDir()
			rs := &Restorer{Options: Options{Registry: restoreRegistry(t)}, Work: t.TempDir()}
			req := backup.LegacyRestore{Archive: bytes.NewReader(raw), Size: int64(len(raw)), Staging: staging,
				SecretKey: []byte(golden.manifest.SecretKey.Value), Ring: ring}
			if _, err := rs.RestoreLegacy(t.Context(), req); !errors.Is(err, backup.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
			if _, err := rs.InspectLegacy(t.Context(), bytes.NewReader(raw), int64(len(raw)), backup.Limits{}); !errors.Is(err, backup.ErrInvalid) {
				t.Fatalf("inspect: %v", err)
			}
			if entries, _ := os.ReadDir(staging); len(entries) != 0 {
				t.Fatalf("something was written: %v", entries)
			}
		})
	}
}

// K3 rest: members below data/GO/, data/Go./ and data/LOGS./ are never
// written, whatever their case (case-insensitive file systems).
func TestExtractIgnoresGoAndLogsInAnyCase(t *testing.T) {
	t.Parallel()
	archive := rewriteArchive(t, backupPath("export"), func(m map[string]any, ms map[string][]byte) {
		for _, p := range []string{"GO/webssh.db", "Go./keyring-material", "LOGS./audit.log", "go/deleted_users/1-x/manifest.json"} {
			data := []byte("planted")
			files := append(m["files"].([]any), map[string]any{"path": p, "sha256": sha256Hex(string(data)), "size": len(data)})
			slices.SortFunc(files, func(a, b any) int {
				return compareStrings(a.(map[string]any)["path"].(string), b.(map[string]any)["path"].(string))
			})
			m["files"] = files
			ms[backupDataPrefix+p] = data
		}
	})
	b, err := OpenBackup(archive, DefaultBackupLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	dest := t.TempDir()
	res, err := ExtractBackup(b, dest, DefaultBackupLimits, RestoreRecoverySnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if res.GoMembers != 3 || res.LogMembers != 1 {
		t.Fatalf("%+v", res)
	}
	for _, name := range []string{"GO", "Go.", "LOGS.", "go", "logs"} {
		if _, err := os.Lstat(filepath.Join(dest, name)); err == nil {
			t.Errorf("%s was written", name)
		}
	}
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// A SECRET_KEY from the environment that does not decrypt the archive's
// records stops the restore before anything is activated (D-08).
func TestRestoreWithForeignEnvironmentSecretStops(t *testing.T) {
	t.Parallel()
	ring, err := keyring.Open([]byte("x"), bytes.Repeat([]byte{3}, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(backupPath("recovery_snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	rs := &Restorer{Options: Options{Registry: restoreRegistry(t)}}
	_, err = rs.RestoreLegacy(context.Background(), backup.LegacyRestore{Archive: f, Size: info.Size(), Staging: t.TempDir(),
		SecretKey: []byte("a different environment secret"), EnvironmentSecret: true, Ring: ring, RecoverySnapshot: true})
	if stopCode(err) != CodeSecretMismatch {
		t.Fatalf("err = %v", err)
	}
}

func TestInspectGoldenBackups(t *testing.T) {
	t.Parallel()
	rs := &Restorer{Work: t.TempDir()}
	for name, want := range map[string]bool{"export": false, "recovery_snapshot": true} {
		f, err := os.Open(backupPath(name))
		if err != nil {
			t.Fatal(err)
		}
		info, _ := f.Stat()
		s, err := rs.InspectLegacy(t.Context(), f, info.Size(), backup.Limits{})
		f.Close()
		if err != nil || !s.Compatible || s.Kind != backup.KindPythonV2 || s.IncludesRemoteCredentials != want || !s.IncludesSecretKey {
			t.Fatalf("%s: %+v, %v", name, s, err)
		}
	}
}

// A build that leaves entities pending cannot restore a Python archive
// that holds records of them: the extraction is removed afterwards, so
// the records would be lost. The restore stops instead.
func TestRestoreRefusesPendingRecords(t *testing.T) {
	t.Parallel()
	material := bytes.Repeat([]byte{0x42}, keyring.MaterialSize)
	ring, err := keyring.Open([]byte(golden.manifest.SecretKey.Value), material)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(backupPath("export"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r := m1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
	rs := &Restorer{Options: Options{Registry: r, Release: "test", Now: func() time.Time { return restoredAt }}, Work: t.TempDir()}
	staging := t.TempDir()
	_, err = rs.RestoreLegacy(t.Context(), backup.LegacyRestore{Archive: f, Size: info.Size(), Staging: staging,
		SecretKey: []byte("the active secret of the new installation"), Ring: ring, RestoredAt: restoredAt})
	stopErr, ok := errors.AsType[*StopError](err)
	if !ok || stopErr.Code != CodeRestoreIncomplete || !strings.Contains(stopErr.Message, "E26") {
		t.Fatalf("restore with pending commands: %v", err)
	}
}
