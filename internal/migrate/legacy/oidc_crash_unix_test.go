//go:build !windows

package legacy

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

const oidcCrashEnv = "WEBSSH_E05_CRASH_IN"

// TestOIDCCrashHelper is the helper process of TestOIDCCrashInStep.
func TestOIDCCrashHelper(t *testing.T) {
	dir := os.Getenv(oidcCrashEnv)
	if dir == "" {
		t.Skip("helper process for the E05 crash test")
	}
	wrap := func(s Step) Step {
		return &failingStep{Step: s, target: "E05", crash: func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }}
	}
	_, err := startClosed(oidcOptions(t, dir, wrap))
	t.Fatalf("no crash in E05: %v", err)
}

// A SIGKILL inside E05 leaves no partial state; the next start migrates
// completely.
func TestOIDCCrashInStep(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestOIDCCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), oidcCrashEnv+"="+dir)
	cmd.Env = append(cmd.Env, helperTempDir(t))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("helper did not fail: %v\n%s", err, out)
	}
	if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("helper ended without SIGKILL: %v\n%s", err, out)
	}
	assertUntouched(t, dir, before)
	o := oidcOptions(t, dir, nil)
	if ev := evaluateOnly(t, o); ev.state != S1 {
		t.Fatalf("state after a crash in E05: %s", ev.state)
	}
	assertNoGoDatabase(t, dir)
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration after the crash: %+v, %v", st, err)
	}
	m := openMigrated(t, dir, golden.manifest.SecretKey.Value, st.Report)
	var n int
	_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM authoidc_identities`).Scan(&n)
	})
	if n != 1 {
		t.Fatalf("%d identities after the crash", n)
	}
}
