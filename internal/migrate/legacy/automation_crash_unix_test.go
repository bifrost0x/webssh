package legacy

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

const automationCrashEnv = "WEBSSH_E29_E31_CRASH_IN"

// TestAutomationCrashHelper is the helper process of
// TestAutomationCrashInStep: it is killed inside the step named by the
// environment.
func TestAutomationCrashHelper(t *testing.T) {
	spec := os.Getenv(automationCrashEnv)
	if spec == "" {
		t.Skip("helper process for the E29/E31 crash test")
	}
	entity, dir := spec[:3], spec[4:]
	wrap := func(s Step) Step {
		return &failingStep{Step: s, target: entity, crash: func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }}
	}
	_, err := startClosed(automationOptions(t, dir, golden.manifest.SecretKey.Value, wrap))
	t.Fatalf("no crash in %s: %v", entity, err)
}

// A SIGKILL inside E29 or E31 leaves no partial state; the next start
// migrates completely.
func TestAutomationCrashInStep(t *testing.T) {
	t.Parallel()
	for _, entity := range []string{"E29", "E31"} {
		dir := copyGolden(t)
		before := legacySnapshot(t, dir)
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAutomationCrashHelper$", "-test.count=1")
		cmd.Env = append(os.Environ(), automationCrashEnv+"="+entity+":"+dir)
		cmd.Env = append(cmd.Env, helperTempDir(t))
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("%s: helper did not fail: %v\n%s", entity, err, out)
		}
		if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("%s: helper ended without SIGKILL: %v\n%s", entity, err, out)
		}
		assertUntouched(t, dir, before)
		o := automationOptions(t, dir, golden.manifest.SecretKey.Value, nil)
		if ev := evaluateOnly(t, o); ev.state != S1 {
			t.Fatalf("%s: state after the crash: %s", entity, ev.state)
		}
		assertNoGoDatabase(t, dir)
		st, err := startClosed(o)
		if err != nil || !st.Migrated {
			t.Fatalf("%s: migration after the crash: %+v, %v", entity, st, err)
		}
		m := openMigrated(t, dir, golden.manifest.SecretKey.Value, st.Report)
		var books, runs int
		_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
			return errors.Join(tx.QueryRowContext(t.Context(), `SELECT count(*) FROM automation_runbooks`).Scan(&books),
				tx.QueryRowContext(t.Context(), `SELECT count(*) FROM automation_runs`).Scan(&runs))
		})
		if books != 2 || runs != 1 {
			t.Fatalf("%s: %d runbooks and %d runs after the crash", entity, books, runs)
		}
	}
}
