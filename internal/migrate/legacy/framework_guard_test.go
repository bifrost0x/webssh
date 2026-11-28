package legacy

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ncruces/go-sqlite3/driver"

	"github.com/bifrost0x/webssh/internal/oracletest"
)

// lockHelperEnv tells TestSQLiteLockHelper what to hold: "<begin>|<path>".
const lockHelperEnv = "WEBSSH_TEST_SQLITE_LOCK"

// pythonLockScript is what the Python release's sqlite3 module does inside
// a write: a transaction that has read from app.db.
const pythonLockScript = "import sqlite3,sys\nc=sqlite3.connect(sys.argv[1],isolation_level=None)\nc.execute(sys.argv[2])\n" +
	"c.execute('SELECT count(*) FROM users').fetchone()\nprint('held',flush=True)\nsys.stdin.read()\n"

// holdPythonLock starts another process inside a transaction on app.db,
// as the Python release holds it during a write, and returns a function
// that ends it. The holder is the Python release's sqlite3 module in live
// mode (internal/oracletest) and otherwise this test binary with the
// SQLite driver: both take SQLite's lock bytes of the same file format,
// which is what the probe looks at.
func holdPythonLock(t *testing.T, appDB, begin string) func() {
	t.Helper()
	var cmd *exec.Cmd
	if oracletest.CurrentMode(t) == oracletest.Replay {
		cmd = exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSQLiteLockHelper$", "-test.count=1") // #nosec G204 -- the test binary itself
		cmd.Env = append(os.Environ(), lockHelperEnv+"="+begin+"|"+appDB)
	} else {
		rel := oracletest.RequireLive(t)
		cmd = exec.CommandContext(t.Context(), rel.Python, "-I", "-c", pythonLockScript, appDB, begin) // #nosec G204 -- test oracle
	}
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "held" {
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("lock holder: %q, %v", line, err)
	}
	return func() { _ = stdin.Close(); _ = cmd.Wait() }
}

// TestSQLiteLockHelper is the lock holder of holdPythonLock: it opens
// app.db, begins the transaction, reads and waits for its stdin to close.
func TestSQLiteLockHelper(t *testing.T) {
	spec := os.Getenv(lockHelperEnv)
	if spec == "" {
		t.Skip("helper process for the lock tests")
	}
	begin, path, _ := strings.Cut(spec, "|")
	db, err := driver.Open("file:" + filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(t.Context(), begin); err != nil {
		t.Fatal(err)
	}
	var users int
	if err := conn.QueryRowContext(t.Context(), "SELECT count(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	fmt.Println("held")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// Section 5.2 step 4 and 8.3: a Python process inside a transaction is
// detected through its SQLite lock, without changing app.db.
func TestPythonHoldingSQLiteLockStops(t *testing.T) {
	t.Parallel()
	for _, begin := range []string{"BEGIN IMMEDIATE", "BEGIN"} {
		dir := copyGolden(t)
		before := legacySnapshot(t, dir)
		release := holdPythonLock(t, filepath.Join(dir, "app.db"), begin)
		_, err := startClosed(testOptions(t, dir))
		release()
		if stopCode(err) != CodeLegacyInUse {
			t.Fatalf("%s: err = %v", begin, err)
		}
		assertUntouched(t, dir, before)
		if _, err := os.Lstat(filepath.Join(dir, "logs", ".webssh-go")); err == nil {
			t.Errorf("%s: material created before the probe", begin)
		}
		if st, err := startClosed(testOptions(t, dir)); err != nil || !st.Migrated {
			t.Fatalf("%s: after Python stopped: %+v, %v", begin, st, err)
		}
	}
}

func TestPythonBackupOperationStops(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	ns, err := BackupNamespace(o.BackupTempDir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ns, 0o700); err != nil {
		t.Fatal(err)
	}
	held, err := acquireLock(filepath.Join(ns, "operation.lock"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = startClosed(o)
	if stopCode(err) != CodeLegacyInUse {
		t.Fatalf("err = %v", err)
	}
	if err := held.release(); err != nil {
		t.Fatal(err)
	}
	if st, err := startClosed(o); err != nil || !st.Migrated {
		t.Fatalf("after the operation: %+v, %v", st, err)
	}
}

// A10: an unfinished Python restore stops the migration; finished ones do
// not. The documents come from the manifest of the legacy fixtures.
func TestPythonRestoreStatus(t *testing.T) {
	t.Parallel()
	for state, doc := range legacyFixture(t).Values.Extended.RestoreStatus.Documents {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			o := testOptions(t, dir)
			ns, err := BackupNamespace(o.BackupTempDir, dir)
			if err != nil {
				t.Fatal(err)
			}
			resolved, _ := resolveLoose(dir)
			body := strings.ReplaceAll(string(doc), "{DATA_FINGERPRINT}", sha256Hex(resolved))
			if err := os.MkdirAll(ns, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ns, "restore-status.json"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = startClosed(o)
			unfinished := legacyFixture(t).Values.Extended.RestoreStatus.Expected[state].MaintenanceActive
			if unfinished != (stopCode(err) == CodeRestorePending) || (!unfinished && err != nil) {
				t.Fatalf("state %s: err = %v, maintenance %v", state, err, unfinished)
			}
		})
	}
}

func TestRestoreStatusRules(t *testing.T) {
	t.Parallel()
	fp := strings.Repeat("a", 64)
	for _, tt := range []struct {
		doc   string
		state string
	}{
		{`{"state":"succeeded","operation_id":"x","message":"m","updated_at":1}`, "succeeded"},
		{`{"state":"failed","operation_id":"x","message":"m","updated_at":1.5,"data_fingerprint":null}`, "failed"},
		{`{"state":"preparing","operation_id":"x","message":"m","updated_at":1,"data_fingerprint":"` + fp + `"}`, "preparing"},
		{`{"state":"preparing","operation_id":"x","message":"m","updated_at":1}`, ""},
		{`{"state":"in_progress","operation_id":"x","message":"m","updated_at":1,"data_fingerprint":"` + fp + `","rollback_relative":"op/rollback.zip"}`, "in_progress"},
		{`{"state":"in_progress","operation_id":"x","message":"m","updated_at":1,"data_fingerprint":"` + fp + `","rollback_relative":"../rollback.zip"}`, ""},
		{`{"state":"succeeded","operation_id":"x","message":"m","updated_at":true}`, ""},
		{`{"state":"succeeded","operation_id":"","message":"m","updated_at":1}`, ""},
		{`{"state":"succeeded","operation_id":"x","message":"m","updated_at":1,"data_fingerprint":"ABC"}`, ""},
		{`{"state":"done","operation_id":"x","message":"m","updated_at":1}`, ""},
		{`{"state":"succeeded","state":"in_progress","operation_id":"x","message":"m","updated_at":1}`, ""},
		{`[]`, ""},
		{"\xff", ""},
	} {
		if got, ok := parseRestoreStatus([]byte(tt.doc)); got != tt.state || ok != (tt.state != "") {
			t.Errorf("%s: %q %v, want %q", tt.doc, got, ok, tt.state)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "restore-status.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := ReadRestoreStatus(dir); err != nil || !st.Unreadable || !st.Unfinished() {
		t.Errorf("unreadable file: %+v, %v", st, err)
	}
	if st, err := ReadRestoreStatus(filepath.Join(dir, "missing")); err != nil || st.Unfinished() {
		t.Errorf("missing namespace: %+v, %v", st, err)
	}
}

// Step 9: a writer that changes a user store during the migration is
// caught by the second digest; nothing is activated.
func TestLegacyChangedDuringMigration(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	o.checkpoint = func(p string) {
		if p == PointWritten {
			path := filepath.Join(dir, "users", "user_3", "settings.json")
			data, _ := os.ReadFile(path)
			data[len(data)-2] = ' '
			_ = os.WriteFile(path, data, 0o600)
		}
	}
	if _, err := startClosed(o); stopCode(err) != CodeChangedDuring {
		t.Fatalf("err = %v", err)
	}
	l := mustLayout(t, dir)
	if ok, _ := l.databasePresent(); ok {
		t.Error("a database was activated")
	}
	if dirs, _ := l.stagingDirs(); len(dirs) != 0 {
		t.Errorf("staging left: %v", dirs)
	}
}

// A02: a wrong SECRET_KEY stops before anything is written.
func TestWrongSecretStopsBeforeWriting(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	o := testOptions(t, dir)
	o.Secret += "x"
	_, err := startClosed(o)
	if stopCode(err) != CodeSecretMismatch || !strings.Contains(err.Error(), "SECRET_KEY does not match the stored data") {
		t.Fatalf("err = %v", err)
	}
	assertUntouched(t, dir, before)
	if _, err := os.Lstat(filepath.Join(dir, "logs", ".webssh-go")); err == nil {
		t.Error("keyring material created with a wrong secret")
	}
	if ok, _ := mustLayout(t, dir).databasePresent(); ok {
		t.Error("database created with a wrong secret")
	}
}

// Section 5.3: a symbolic link anywhere in the legacy source is STOP.
func TestSymlinkInSourceStops(t *testing.T) {
	t.Parallel()
	for _, link := range []struct{ name, target string }{
		{"users/user_3/notes.json", "/etc/passwd"},
		{"users/user_99", "user_3"},
	} {
		dir := copyGolden(t)
		if err := os.Symlink(link.target, filepath.Join(dir, link.name)); err != nil {
			t.Fatal(err)
		}
		before := legacySnapshot(t, dir)
		if _, err := startClosed(testOptions(t, dir)); stopCode(err) != CodeUnsafeSource {
			t.Fatalf("%s: err = %v", link.name, err)
		}
		assertUntouched(t, dir, before)
	}
}

// After activation a new symbolic link is a change of the source (S3).
func TestSymlinkAfterActivationIsAChange(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("user_3", filepath.Join(dir, "users", "user_77")); err != nil {
		t.Fatal(err)
	}
	if _, err := startClosed(o); stopCode(err) != CodeLegacyChanged {
		t.Fatalf("err = %v", err)
	}
}

// Section 8.3 "full disk": the space check refuses up front and writes
// nothing.
func TestNotEnoughSpaceStopsUpFront(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	o.freeSpace = func(string) (uint64, error) { return spaceMargin, nil }
	_, err := startClosed(o)
	if stopCode(err) != CodeNoSpace || !strings.Contains(err.Error(), "bytes on the file system") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "logs", ".webssh-go")); err == nil {
		t.Error("material created although the space check failed")
	}
}

// A dry run reports without activating and leaves no material, database
// or staging behind.
func TestDryRun(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	rep, err := DryRun(t.Context(), testOptions(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result != ResultDryRun || len(rep.Entities) != 3 || !rep.LegacyUntouched.Equal {
		t.Fatalf("report %+v", rep)
	}
	assertUntouched(t, dir, before)
	l := mustLayout(t, dir)
	if ok, _ := l.databasePresent(); ok {
		t.Error("dry run activated a database")
	}
	if dirs, _ := l.stagingDirs(); len(dirs) != 0 {
		t.Errorf("staging left: %v", dirs)
	}
	if _, err := os.Lstat(l.stateDir); err == nil {
		t.Error("dry run created logs/.webssh-go/")
	}
}

// Section 8.3 "read-only legacy files": the migration succeeds when every
// legacy file and directory except logs/ and go/ is read-only.
func TestReadOnlyLegacyData(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	dir := copyGolden(t)
	var dirs []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		rel, _ := filepath.Rel(dir, p)
		if err != nil || rel == "." || goOwned(filepath.ToSlash(rel)) || strings.HasPrefix(filepath.ToSlash(rel), "logs/") {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, p)
			return nil
		}
		return os.Chmod(p, 0o400)
	})
	for _, dir := range slices.Backward(dirs) {
		_ = os.Chmod(dir, 0o500)
	}
	t.Cleanup(func() {
		for _, d := range dirs {
			_ = os.Chmod(d, 0o700)
		}
	})
	before := legacySnapshot(t, dir)
	if st, err := startClosed(testOptions(t, dir)); err != nil || !st.Migrated {
		t.Fatalf("%+v, %v", st, err)
	}
	assertUntouched(t, dir, before)
}

// Stale side files of an earlier database at the target are moved aside
// byte for byte, whether they were there before the run or appear before
// the activation (step 10.4), and the new database opens clean.
func TestStaleSideFilesAreMovedAside(t *testing.T) {
	t.Parallel()
	for _, late := range []bool{false, true} {
		dir := copyGolden(t)
		o := testOptions(t, dir)
		plant := func() {
			for _, side := range []string{"-wal", "-shm"} {
				if err := os.WriteFile(filepath.Join(dir, "go", "webssh.db"+side), []byte("stale "+side), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		if late {
			o.checkpoint = func(p string) {
				if p == PointCommitted {
					plant()
				}
			}
		} else {
			if err := os.MkdirAll(filepath.Join(dir, "go"), 0o700); err != nil {
				t.Fatal(err)
			}
			plant()
		}
		if st, err := startClosed(o); err != nil || !st.Migrated {
			t.Fatalf("late %v: %+v, %v", late, st, err)
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "go", "replaced-*", "webssh.db-wal"))
		if len(matches) != 1 {
			t.Fatalf("late %v: stale WAL not moved aside: %v", late, matches)
		}
		if data, _ := os.ReadFile(matches[0]); string(data) != "stale -wal" {
			t.Errorf("moved WAL changed: %q", data)
		}
		o.checkpoint = nil
		if st, err := startClosed(o); err != nil || st.State != S2 {
			t.Fatalf("late %v: %+v, %v", late, st, err)
		}
	}
}

func TestGoLockRefusesSecondProcess(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	st := mustStart(t, o)
	if _, err := Replace(t.Context(), o); stopCode(err) != CodeLocked {
		t.Fatalf("replace beside a running Go: %v", err)
	}
	if _, err := DryRun(t.Context(), o); stopCode(err) != CodeLocked {
		t.Fatalf("dry run beside a running Go: %v", err)
	}
	_ = st.Close()
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
