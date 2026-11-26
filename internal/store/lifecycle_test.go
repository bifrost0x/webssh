package store_test

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"

	_ "github.com/ncruces/go-sqlite3/driver"
)

func sideFiles(t *testing.T, path string) []string {
	t.Helper()
	var left []string
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			left = append(left, suffix)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	return left
}

func openHosts(t *testing.T, path string) *store.DB {
	t.Helper()
	db, err := store.Open(t.Context(), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyAll(t.Context(), hostsSchema); err != nil {
		t.Fatal(err)
	}
	return db
}

func insertProfile(t *testing.T, db *store.DB, id string) {
	t.Helper()
	err := db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO hosts_profiles VALUES (?, ?)`, id, "name-"+id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCloseLeavesOneFile: the shutdown close leaves only the database file,
// which then opens read-only as immutable with all data (what a Python
// backup of a stopped Go copies).
func TestCloseLeavesOneFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "webssh.db")
	db := openHosts(t, path)
	insertProfile(t, db, "a")
	if left := sideFiles(t, path); len(left) == 0 {
		t.Fatal("database is not in WAL mode while open")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if left := sideFiles(t, path); len(left) != 0 {
		t.Fatalf("side files after Close: %v", left)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := db.Write(t.Context(), func(*store.Tx) error { return nil }); err == nil {
		t.Fatal("Write after Close succeeded")
	}
	ro, err := store.OpenReadOnly(t.Context(), path, store.Immutable)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	var n int
	if err := ro.QueryRowContext(t.Context(), `SELECT count(*) FROM hosts_profiles`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("copy after Close: %d rows, %v", n, err)
	}
}

// TestCloseWaitsForWriters closes while writers run: every write either
// committed before the close or fails cleanly, and the file is complete.
func TestCloseWaitsForWriters(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "webssh.db")
	db := openHosts(t, path)
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		committed int
	)
	for w := range 8 {
		wg.Go(func() {
			for i := range 50 {
				err := db.Write(t.Context(), func(tx *store.Tx) error {
					_, err := tx.ExecContext(t.Context(), `INSERT INTO hosts_profiles VALUES (?, ?)`, fmt.Sprint(w, "-", i), fmt.Sprint(w, i))
					return err
				})
				if err != nil {
					return
				}
				mu.Lock()
				committed++
				mu.Unlock()
			}
		})
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if left := sideFiles(t, path); len(left) != 0 {
		t.Fatalf("side files: %v", left)
	}
	again := openHosts(t, path)
	defer again.Close()
	if n := count(t, again, `SELECT count(*) FROM hosts_profiles`); n != committed {
		t.Fatalf("%d rows, %d writes reported committed", n, committed)
	}
	if err := again.QuickCheck(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestReadersDuringWrites runs readers against serialized writers: every
// snapshot is consistent (both tables move together).
func TestReadersDuringWrites(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, store.Schema{Owner: "settings", Migrations: []store.Migration{
		{Version: 1, SQL: `CREATE TABLE settings_a (n INTEGER NOT NULL) STRICT; CREATE TABLE settings_b (n INTEGER NOT NULL) STRICT;
			INSERT INTO settings_a VALUES (0); INSERT INTO settings_b VALUES (0)`},
	}})
	ctx := t.Context()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 50 {
				err := db.Write(ctx, func(tx *store.Tx) error {
					if _, err := tx.ExecContext(ctx, `UPDATE settings_a SET n = n + 1`); err != nil {
						return err
					}
					_, err := tx.ExecContext(ctx, `UPDATE settings_b SET n = n + 1`)
					return err
				})
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
	for range 8 {
		wg.Go(func() {
			for range 100 {
				var a, b int
				err := db.Read(ctx, func(tx *store.Tx) error {
					if err := tx.QueryRowContext(ctx, `SELECT n FROM settings_a`).Scan(&a); err != nil {
						return err
					}
					return tx.QueryRowContext(ctx, `SELECT n FROM settings_b`).Scan(&b)
				})
				if err != nil {
					t.Error(err)
				} else if a != b {
					t.Errorf("inconsistent snapshot: %d and %d", a, b)
				}
			}
		})
	}
	wg.Wait()
	if n := count(t, db, `SELECT n FROM settings_b`); n != 200 {
		t.Fatalf("counter %d, want 200", n)
	}
}

func TestOpenRefusesNonRegularPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.db")
	db := openHosts(t, target)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if _, err := store.Open(t.Context(), link, store.Options{}); !errors.Is(err, store.ErrNotRegular) {
		t.Errorf("symlinked database: %v", err)
	}
	if _, err := store.Open(t.Context(), dir, store.Options{}); !errors.Is(err, store.ErrNotRegular) {
		t.Errorf("directory as database: %v", err)
	}
	realDir := filepath.Join(dir, "real-go")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "go")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(t.Context(), filepath.Join(linkDir, "webssh.db"), store.Options{}); !errors.Is(err, store.ErrNotRegular) {
		t.Errorf("database in a symlinked directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(realDir, "webssh.db")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a database was created through the symlink")
	}
}

func TestChecks(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, hostsSchema)
	insertProfile(t, db, "a")
	if err := db.QuickCheck(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := db.IntegrityCheck(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestForeignKeyCheckReportsDanglingRows(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "webssh.db")
	db := openHosts(t, path)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// A dangling row written by a connection without enforcement, as in a
	// hand-edited file.
	raw, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_pragma=foreign_keys(0)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(t.Context(), `INSERT INTO hosts_tags VALUES ('missing', 't')`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := store.Open(t.Context(), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.QuickCheck(t.Context()); err != nil {
		t.Fatalf("quick_check does not cover foreign keys: %v", err)
	}
	if err := again.IntegrityCheck(t.Context()); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("IntegrityCheck: %v", err)
	}
}

// TestCheckFindsDamage overwrites the data pages of a closed database.
func TestCheckFindsDamage(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "webssh.db")
	db := openHosts(t, path)
	for i := range 200 {
		insertProfile(t, db, fmt.Sprint(i))
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the header page; scramble everything after it.
	junk := make([]byte, info.Size()-4096)
	for i := range junk {
		junk[i] = byte(i*7 + 3)
	}
	if _, err := f.WriteAt(junk, 4096); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	damaged, err := store.Open(t.Context(), path, store.Options{})
	if err != nil {
		t.Logf("damaged file refused at open: %v", err)
		return // refusing to open is also a detection
	}
	defer damaged.Close()
	if err := damaged.QuickCheck(t.Context()); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("QuickCheck on a damaged file: %v", err)
	}
}
