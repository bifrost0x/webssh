package legacy

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

const m1CrashEnv = "WEBSSH_M1_CRASH_IN"

// TestM1CrashHelper is the helper process of TestM1CrashInEveryStep: it
// migrates with the M1 registry and kills itself with SIGKILL inside the
// named step, after the step wrote into the staging transaction.
func TestM1CrashHelper(t *testing.T) {
	spec := os.Getenv(m1CrashEnv)
	if spec == "" {
		t.Skip("helper process for the M1 crash test")
	}
	entity, dir, _ := strings.Cut(spec, "|")
	m := M1{Persistent: &testPersistent{}}
	m.wrap = func(s Step) Step {
		return &failingStep{Step: s, target: entity, crash: func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }}
	}
	_, err := startClosed(m1Options(t, dir, m))
	t.Fatalf("no crash in %s: %v", entity, err)
}

// A SIGKILL inside any step leaves no partial state: the next start finds
// S1 (no Go database, the staging directory is cleaned as S6), migrates
// completely, and the legacy data never changed.
func TestM1CrashInEveryStep(t *testing.T) {
	t.Parallel()
	for _, entity := range m1Entities(t) {
		t.Run(entity, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			before := legacySnapshot(t, dir)
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestM1CrashHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), m1CrashEnv+"="+entity+"|"+dir)
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
			o := m1Options(t, dir, M1{Persistent: &testPersistent{}})
			if ev := evaluateOnly(t, o); ev.state != S1 {
				t.Fatalf("state after a crash in %s: %s", entity, ev.state)
			}
			assertNoGoDatabase(t, dir)
			st, err := startClosed(o)
			if err != nil || !st.Migrated {
				t.Fatalf("restart: %+v, %v", st, err)
			}
			assertUntouched(t, dir, before)
		})
	}
}
