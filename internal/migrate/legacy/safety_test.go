package legacy

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3/driver"
)

// copyGolden returns a private copy of the golden DATA_DIR.
func copyGolden(t *testing.T) string {
	t.Helper()
	dest := t.TempDir()
	if err := extractTar(filepath.Join(fixtureDir, "datadir.tar"), dest); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dest, "data")
}

// execSQL changes a test database (never a fixture file in place).
func execSQL(t *testing.T, path string, statements ...string) {
	t.Helper()
	db, err := driver.Open("file:" + filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range statements {
		if _, err := db.ExecContext(t.Context(), s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

// Specification 8.3: a symlinked user directory or key file is STOP.
func TestSymlinksStop(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		link func(t *testing.T, dir string)
	}{
		{"user directory users/user_3 -> user_5", func(t *testing.T, dir string) {
			users := filepath.Join(dir, "users")
			if err := os.RemoveAll(filepath.Join(users, "user_3")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("user_5", filepath.Join(users, "user_3")); err != nil {
				t.Fatal(err)
			}
		}},
		{"key file", func(t *testing.T, dir string) {
			keys := filepath.Join(dir, "users", "user_3", "keys")
			target := filepath.Join(keys, "9971eb1e-92db-4b73-93dd-b5c5d5d8387c.pem")
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("168716ca-55b4-4155-8827-f5d378fe0ad0.pem", target); err != nil {
				t.Fatal(err)
			}
		}},
		{"store outside DATA_DIR", func(t *testing.T, dir string) {
			store := filepath.Join(dir, "users", "user_3", "profiles.json")
			if err := os.Remove(store); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/hostname", store); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			tt.link(t, dir)
			if src, err := Open(t.Context(), dir, golden.manifest.SecretKey.Value); !errors.Is(err, ErrUnsafePath) {
				if src != nil {
					src.Close()
				}
				t.Fatalf("err = %v, want ErrUnsafePath", err)
			}
		})
	}
}

// The per-file check holds on its own as well (a link created after Open).
func TestReadLimitedRefusesLinksAndSpecialFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "users", "user_5"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users", "user_5", "profiles.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("user_5", filepath.Join(dir, "users", "user_3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "users", "user_5", "settings.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"users/user_3/profiles.json", "users/user_5/settings.json"} {
		if _, err := readLimited(root, name, maxFileBytes); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%s: err = %v, want ErrUnsafePath", name, err)
		}
	}
	if _, err := readLimited(root, "users/user_5/profiles.json", maxFileBytes); err != nil {
		t.Fatal(err)
	}
}

// snapshot lists every entry below dir with size and modification time.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = fmt.Sprint(info.Mode(), info.ModTime().Format(time.RFC3339Nano), info.Size())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func minimalDatabase(t *testing.T, dir string, wal bool) string {
	t.Helper()
	path := filepath.Join(dir, "app.db")
	stmts := []string{"CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, created_at DATETIME, last_login DATETIME)",
		"INSERT INTO users VALUES (1, 'a', '$2b$12$x', '2026-11-02 09:00:00.000000', NULL)"}
	if wal {
		stmts = append([]string{"PRAGMA journal_mode = WAL"}, stmts...)
		stmts = append(stmts, "PRAGMA wal_checkpoint(TRUNCATE)")
	}
	execSQL(t, path, stmts...)
	for _, side := range []string{"-wal", "-shm"} {
		_ = os.Remove(path + side) // left by the writer; a clean shutdown removes them
	}
	return path
}

// Invariant I-01: reading writes nothing into DATA_DIR, also for a
// database in WAL mode, which SQLite would otherwise give -wal and -shm.
func TestOpenWritesNothing(t *testing.T) {
	t.Parallel()
	for _, wal := range []bool{false, true} {
		dir := t.TempDir()
		minimalDatabase(t, dir, wal)
		before := snapshot(t, dir)
		src, err := Open(t.Context(), dir, "secret")
		if err != nil {
			t.Fatal(err)
		}
		if users, err := src.Users(t.Context()); err != nil || len(users) != 1 || !users[0].IsAdmin {
			t.Fatalf("wal %v: users %+v, %v", wal, users, err)
		}
		if err := src.Close(); err != nil {
			t.Fatal(err)
		}
		after := snapshot(t, dir)
		if len(after) != len(before) {
			t.Fatalf("wal %v: entries %d -> %d", wal, len(before), len(after))
		}
		for p, v := range before {
			if after[p] != v {
				t.Fatalf("wal %v: %s changed", wal, p)
			}
		}
	}
	golden := copyGolden(t)
	before := snapshot(t, golden)
	src, err := Open(t.Context(), golden, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Tables(t.Context()); err != nil {
		t.Fatal(err)
	}
	src.Close()
	if after := snapshot(t, golden); len(after) != len(before) {
		t.Fatal("golden DATA_DIR changed")
	}
}

func TestUnfinishedJournalStops(t *testing.T) {
	t.Parallel()
	for _, side := range []string{"app.db-journal", "app.db-wal"} {
		dir := t.TempDir()
		minimalDatabase(t, dir, side == "app.db-wal")
		if err := os.WriteFile(filepath.Join(dir, side), []byte("pending"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(t.Context(), dir, "secret"); !errors.Is(err, ErrJournal) {
			t.Errorf("%s: err = %v, want ErrJournal", side, err)
		}
		// An empty journal is what SQLite leaves after a commit: fine.
		if err := os.WriteFile(filepath.Join(dir, side), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		src, err := Open(t.Context(), dir, "secret")
		if err != nil {
			t.Errorf("%s empty: %v", side, err)
			continue
		}
		src.Close()
	}
}

// Specification 5.2 step 3: triggers and views are reported in the live
// source (3.3.x runs with them) and rejected when restoring a backup.
func TestTriggersAndViewsAreReported(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	sql := append([]string{"CREATE TABLE operator_notes (id INTEGER PRIMARY KEY, note TEXT)"},
		legacyFixture(t).Variants["database_trigger_and_view"].SQL...)
	if len(sql) < 3 {
		t.Fatal("variant database_trigger_and_view missing from the legacy manifest")
	}
	execSQL(t, filepath.Join(dir, "app.db"), sql...)
	src := openLegacy(t, dir)
	sc := src.Schema()
	if len(sc.Triggers) != 1 || len(sc.Views) != 1 {
		t.Fatalf("schema %+v", sc)
	}
	if err := src.CheckBackupDatabase(t.Context()); !errors.Is(err, ErrBackup) {
		t.Fatalf("backup check: %v", err)
	}
}

func TestUnknownOrMissingColumnsStop(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, sql string }{
		{"unknown column in a migrated table", "ALTER TABLE recovery_codes ADD COLUMN newer_release TEXT"},
		{"unknown users column", "ALTER TABLE users ADD COLUMN newer_release TEXT"},
		{"missing column Python does not add", "ALTER TABLE webauthn_credentials DROP COLUMN transports"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			execSQL(t, filepath.Join(dir, "app.db"), tt.sql)
			if src, err := Open(t.Context(), dir, "secret"); err == nil {
				src.Close()
				t.Fatal("opened")
			}
		})
	}
}

func TestKeyFileMissingStops(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	if err := os.Remove(filepath.Join(dir, "users", "user_3", "keys", "9971eb1e-92db-4b73-93dd-b5c5d5d8387c.pem")); err != nil {
		t.Fatal(err)
	}
	src := openLegacy(t, dir)
	if _, err := src.SSHKeys(3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestPendingDeletionEntryMustBeAFile(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	pending := ".delete-" + strings.Repeat("a", 32) + "-9971eb1e-92db-4b73-93dd-b5c5d5d8387c.pem"
	if err := os.Mkdir(filepath.Join(dir, "users", "user_3", "keys", pending), 0o700); err != nil {
		t.Fatal(err)
	}
	src := openLegacy(t, dir)
	if _, err := src.SSHKeys(3); err == nil {
		t.Fatal("directory accepted as pending deletion")
	}
}

// rawZip builds an archive with one stored member whose header declares
// the given uncompressed size, so the ratio check runs before reading.
func rawZip(t *testing.T, stored []byte, declared uint64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{Name: "data/app.db", Method: zip.Deflate,
		CompressedSize64: uint64(len(stored)), UncompressedSize64: declared})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(stored); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCompressionRatioBoundary(t *testing.T) {
	t.Parallel()
	stored := bytes.Repeat([]byte{0}, 10)
	tests := []struct {
		name     string
		declared uint64
		ratioErr bool
	}{
		{"exactly 200", 2000, false},
		{"one byte above 200", 2001, true},
		{"just below 201 (integer division would pass)", 2009, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archive := rawZip(t, stored, tt.declared)
			_, err := OpenBackupReader(bytes.NewReader(archive), int64(len(archive)), DefaultBackupLimits)
			if !errors.Is(err, ErrBackup) {
				t.Fatalf("err = %v", err)
			}
			if got := strings.Contains(err.Error(), "compression ratio"); got != tt.ratioErr {
				t.Fatalf("ratio error %v: %v", got, err)
			}
		})
	}
}

func FuzzOpenBackupReader(f *testing.F) {
	for _, name := range []string{"export.zip", "online.zip"} {
		if data, err := os.ReadFile(filepath.Join(fixtureDir, "artifacts", "backups", name)); err == nil {
			f.Add(data)
		}
	}
	if data, err := os.ReadFile(filepath.Join(legacyFixtureDir, "backups", "backup-v1-8c41517.zip")); err == nil {
		f.Add(data)
	}
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))
	limits := DefaultBackupLimits
	limits.TotalSize, limits.FileSize = 4<<20, 2<<20 // keep each run small
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := OpenBackupReader(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			if !errors.Is(err, ErrBackup) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		for _, file := range b.Manifest.Files {
			if !safeBackupPath(file.Path) || file.Size > limits.FileSize {
				t.Fatalf("accepted %q (%d bytes)", file.Path, file.Size)
			}
		}
	})
}

// A pending deletion whose key file still exists is discarded, as Python
// discards it; the key is read from its own file.
func TestPendingDeletionBesideExistingKeyIsDiscarded(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	keys := filepath.Join(dir, "users", "user_3", "keys")
	pending := ".delete-" + strings.Repeat("b", 32) + "-9971eb1e-92db-4b73-93dd-b5c5d5d8387c.pem"
	if err := os.WriteFile(filepath.Join(keys, pending), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := openLegacy(t, dir).SSHKeys(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Pending) != 1 || store.Pending[0].Restored {
		t.Fatalf("pending %+v", store.Pending)
	}
	for _, k := range store.Keys {
		if k.RecoveredFrom != "" || k.State != KeyUsable {
			t.Fatalf("key %s read from %q", k.ID, k.RecoveredFrom)
		}
	}
}
