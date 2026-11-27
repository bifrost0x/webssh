package legacy

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

const schedulesCrashEnv = "WEBSSH_E15_CRASH_IN"

func schedulesOptions(t *testing.T, dir string, crash bool) Options {
	t.Helper()
	o := testOptions(t, dir)
	r := credentialsRegistry(t)
	if crash {
		r.Schemas(session.Schema(), automation.Schema())
		wrap := &failingStep{Step: &schedulesStep{}, target: "E15", crash: func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }}
		if err := r.Add(GroupAutomation, func() Step { return wrap }); err != nil {
			t.Fatal(err)
		}
	} else if err := AddSchedules(r); err != nil {
		t.Fatal(err)
	}
	o.Registry = r
	o.Secret = golden.manifest.SecretKey.Value
	return o
}

// TestSchedulesCrashHelper is the helper process of TestSchedulesCrashInStep.
func TestSchedulesCrashHelper(t *testing.T) {
	dir := os.Getenv(schedulesCrashEnv)
	if dir == "" {
		t.Skip("helper process for the E15 crash test")
	}
	_, err := startClosed(schedulesOptions(t, dir, true))
	t.Fatalf("no crash in E15: %v", err)
}

// A SIGKILL inside E15 leaves no partial state; the next start migrates
// completely.
func TestSchedulesCrashInStep(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSchedulesCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), schedulesCrashEnv+"="+dir)
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
	o := schedulesOptions(t, dir, false)
	if ev := evaluateOnly(t, o); ev.state != S1 {
		t.Fatalf("state after a crash in E15: %s", ev.state)
	}
	assertNoGoDatabase(t, dir)
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration after the crash: %+v, %v", st, err)
	}
	m := openMigrated(t, dir, golden.manifest.SecretKey.Value, st.Report)
	var n int
	_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM automation_schedules`).Scan(&n)
	})
	if n != 2 {
		t.Fatalf("%d schedules after the crash", n)
	}
}
