package legacy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// crashEnv tells the helper process where to kill itself:
// "<mode>|<point>|<DATA_DIR>|<BACKUP_TEMP_DIR>".
const crashEnv = "WEBSSH_MIGRATION_CRASH_AT"

// TestCrashHelper is the helper process of the crash tests: it runs Start
// or Replace and sends itself SIGKILL at the named checkpoint.
func TestCrashHelper(t *testing.T) {
	spec := os.Getenv(crashEnv)
	if spec == "" {
		t.Skip("helper process for the crash tests")
	}
	parts := strings.Split(spec, "|")
	o := testOptions(t, parts[2])
	o.BackupTempDir = parts[3]
	o.checkpoint = func(p string) {
		if p == parts[1] {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	}
	var err error
	switch parts[0] {
	case "start":
		_, err = startClosed(o)
	case "replace":
		_, err = Replace(context.Background(), o)
	case "purge":
		_, err = Purge(context.Background(), PurgeOptions{Options: o, SkipBackup: true})
	}
	t.Fatalf("no crash at %s: %v", parts[1], err)
}

// crashAt runs the helper and checks that it died from SIGKILL.
func crashAt(t *testing.T, mode, point string, o Options) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), crashEnv+"="+strings.Join([]string{mode, point, o.DataDir, o.BackupTempDir}, "|"))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("%s %s: helper did not fail: %v\n%s", mode, point, err, out)
	}
	ws, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("%s %s: helper ended without SIGKILL: %v\n%s", mode, point, err, out)
	}
}

var startPoints = []string{
	PointLocked, PointStagingClean, PointRead, PointMaterial, PointStaged, PointWritten, PointCommitted,
	PointClosed, PointSideFilesMove, PointRenamed, PointDirSynced, PointMarker, PointStagingGone, PointReport,
}

// afterRename reports whether a crash at point leaves the new database.
func afterRename(point string) bool {
	return slices.Index(startPoints, point) >= slices.Index(startPoints, PointRenamed)
}

// evaluateOnly returns the state the next start finds, after the S6
// clean-up, without migrating.
func evaluateOnly(t *testing.T, o Options) evaluation {
	t.Helper()
	l, lock, _, err := lockAndClean(o)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
	ev, err := evaluate(t.Context(), l, o.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// A SIGKILL at every transition of the first migration ends in S1 (with
// staging, removed as S6) or S2, never in a mixed state, and the next start
// completes the migration. The legacy data never changes (section 8.3).
func TestCrashDuringMigration(t *testing.T) {
	t.Parallel()
	for _, point := range startPoints {
		t.Run(point, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			o := testOptions(t, dir)
			before := legacySnapshot(t, dir)
			crashAt(t, "start", point, o)
			assertUntouched(t, dir, before)
			ev := evaluateOnly(t, o)
			want := S1
			if afterRename(point) {
				want = S2
			}
			if ev.state != want {
				t.Fatalf("state after a crash at %s: %s, want %s (%v)", point, ev.state, want, ev.stop)
			}
			st, err := startClosed(o)
			if err != nil || st.State != S2 {
				t.Fatalf("restart: %+v, %v", st, err)
			}
			if st.Migrated == afterRename(point) {
				t.Errorf("migrated again: %v", st.Migrated)
			}
			if m, err := readMarker(mustLayout(t, dir)); err != nil || m == nil || m.DatabaseID == "unknown" {
				t.Errorf("marker after restart: %+v, %v", m, err)
			}
			if dirs, _ := mustLayout(t, dir).stagingDirs(); len(dirs) != 0 {
				t.Errorf("staging left: %v", dirs)
			}
			assertUntouched(t, dir, before)
			assertRegularOnly(t, dir)
		})
	}
}

// A SIGKILL at every transition of --replace leaves the old database (S3)
// or the new one (S2).
func TestCrashDuringReplace(t *testing.T) {
	t.Parallel()
	points := append([]string{PointReplacedSaved}, startPoints...)
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			o := testOptions(t, dir)
			if _, err := startClosed(o); err != nil {
				t.Fatal(err)
			}
			old := evaluateOnly(t, o).record.DatabaseID
			touchLegacy(t, dir)
			before := legacySnapshot(t, dir)
			crashAt(t, "replace", point, o)
			assertUntouched(t, dir, before)
			ev := evaluateOnly(t, o)
			switch {
			case point != PointReplacedSaved && afterRename(point):
				if ev.state != S2 || ev.record.DatabaseID == old {
					t.Fatalf("after a crash at %s: %s, database %s", point, ev.state, ev.record.DatabaseID)
				}
			default:
				if ev.state != S3 || ev.record.DatabaseID != old {
					t.Fatalf("after a crash at %s: %s, want the old database in S3", point, ev.state)
				}
				if _, err := Replace(t.Context(), o); err != nil {
					t.Fatalf("replace again: %v", err)
				}
			}
			if st, err := startClosed(o); err != nil || st.State != S2 {
				t.Fatalf("restart: %+v, %v", st, err)
			}
			assertUntouched(t, dir, before)
		})
	}
}

// walEnv makes TestWALHelper write one row into the Go database and die
// with SIGKILL, as a server killed while it runs leaves its WAL.
const walEnv = "WEBSSH_MIGRATION_WAL_DB"

func TestWALHelper(t *testing.T) {
	path := os.Getenv(walEnv)
	if path == "" {
		t.Skip("helper process for the WAL test")
	}
	db, err := store.Open(context.Background(), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Write(context.Background(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO hostops_c7_keys VALUES ('wal-row', 0, x'00')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}

// M3: --replace on a database a crash left in WAL state keeps a copy that
// holds the committed rows of the WAL.
func TestReplaceKeepsWALContent(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "go", "webssh.db")
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestWALHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), walEnv+"="+dbPath)
	_ = cmd.Run()
	if info, err := os.Stat(dbPath + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("no WAL left by the killed server: %v", err)
	}
	touchLegacy(t, dir)
	res, err := Replace(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if side, _ := filepath.Glob(filepath.Join(filepath.Dir(res.Database), "webssh.db-*")); len(side) != 0 {
		t.Errorf("side files beside the kept copy: %v", side)
	}
	// The kept database is a Go backup that opens with this installation's
	// SECRET_KEY and material (C7).
	_, material, err := keyring.MaterialLocation(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	keptDB := filepath.Join(t.TempDir(), "kept.db")
	if _, err := backup.VerifyWith(t.Context(), res.Database, backup.VerifyOptions{Secret: []byte(o.Secret), Material: material,
		Database: keptDB}); err != nil {
		t.Fatalf("the kept backup does not verify: %v", err)
	}
	kept, err := store.OpenReadOnly(t.Context(), keptDB, store.Shared)
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	var n int
	if err := kept.QueryRowContext(t.Context(), `SELECT count(*) FROM hostops_c7_keys WHERE id = 'wal-row'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the kept copy lacks the WAL row: %d, %v", n, err)
	}
}
