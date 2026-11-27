package store_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

const crashEnv = "WEBSSH_STORE_CRASH_DB"

// TestCrashChild is the process TestCrashRecovery kills. It commits 100
// rows, starts a write transaction with one more row, reports "ready" and
// waits to be killed inside the transaction.
func TestCrashChild(t *testing.T) {
	path := os.Getenv(crashEnv)
	if path == "" {
		t.Skip("helper process of TestCrashRecovery")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyAll(ctx, hostsSchema); err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		if err := db.Write(ctx, func(tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO hosts_profiles VALUES (?, ?)`, fmt.Sprint(i), fmt.Sprint("n", i))
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hosts_profiles VALUES ('uncommitted', 'x')`); err != nil {
			return err
		}
		fmt.Println("ready")
		select {}
	})
}

// TestCrashRecovery kills a writer in the middle of a transaction, then
// checks that the next start sees exactly the committed state, passes
// quick_check, and that the activation close leaves a single, complete
// file (migration specification, 5.2 step 10).
func TestCrashRecovery(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "webssh.db")
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), crashEnv+"="+path)
	cmd.Env = append(cmd.Env, helperTempDir(t))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(out)
	ready := false
	for scanner.Scan() {
		if scanner.Text() == "ready" {
			ready = true
			break
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if !ready {
		t.Fatal("helper did not reach the open transaction")
	}
	if left := sideFiles(t, path); len(left) == 0 {
		t.Fatal("no WAL after the crash; the test does not exercise recovery")
	}

	db, err := store.Open(t.Context(), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QuickCheck(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := db.IntegrityCheck(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, `SELECT count(*) FROM hosts_profiles`); n != 100 {
		t.Fatalf("%d rows after the crash, want the 100 committed", n)
	}
	if n := count(t, db, `SELECT count(*) FROM hosts_profiles WHERE id = 'uncommitted'`); n != 0 {
		t.Fatal("uncommitted row survived the crash")
	}
	if err := db.CloseForActivation(t.Context()); err != nil {
		t.Fatal(err)
	}
	if left := sideFiles(t, path); len(left) != 0 {
		t.Fatalf("side files after activation close: %v", left)
	}
	if err := db.CloseForActivation(t.Context()); err == nil {
		t.Fatal("second activation close succeeded")
	}
	ro, err := store.OpenReadOnly(t.Context(), path, store.Immutable)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	var n int
	if err := ro.QueryRowContext(t.Context(), `SELECT count(*) FROM hosts_profiles`).Scan(&n); err != nil || n != 100 {
		t.Fatalf("activated file alone: %d rows, %v", n, err)
	}
	if _, err := os.Lstat(path + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reading the activated file created a WAL")
	}
}
