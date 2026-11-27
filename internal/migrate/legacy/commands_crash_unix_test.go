package legacy

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/bifrost0x/webssh/internal/commands"
	"github.com/bifrost0x/webssh/internal/store"
)

const commandsCrashEnv = "WEBSSH_COMMANDS_CRASH_IN"

// commandsOptions migrate with the commands area; with crash, the process
// kills itself inside the step of entity crash.
func commandsOptions(t *testing.T, dir, crash string) Options {
	t.Helper()
	o := testOptions(t, dir)
	r := m1Registry(t, M1{})
	if crash != "" {
		r.Schemas(commands.Schema())
		kill := func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }
		for _, s := range []Step{&commandsStep{}, &commandSetsStep{}} {
			wrap := &failingStep{Step: s, target: crash, crash: kill}
			if err := r.Add(GroupCommands, func() Step { return wrap }); err != nil {
				t.Fatal(err)
			}
		}
	} else if err := AddCommands(r); err != nil {
		t.Fatal(err)
	}
	o.Registry = r
	o.Secret = golden.manifest.SecretKey.Value
	return o
}

// TestCommandsCrashHelper is the helper process of TestCommandsCrashInStep.
func TestCommandsCrashHelper(t *testing.T) {
	dir, entity := os.Getenv(commandsCrashEnv), os.Getenv(commandsCrashEnv+"_ENTITY")
	if dir == "" {
		t.Skip("helper process for the E26/E27 crash test")
	}
	_, err := startClosed(commandsOptions(t, dir, entity))
	t.Fatalf("no crash in %s: %v", entity, err)
}

// A SIGKILL inside E26 or E27 leaves no partial state; the next start
// migrates every command and set (CM1-2).
func TestCommandsCrashInStep(t *testing.T) {
	t.Parallel()
	for _, entity := range []string{"E26", "E27"} {
		t.Run(entity, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			before := legacySnapshot(t, dir)
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCommandsCrashHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), commandsCrashEnv+"="+dir, commandsCrashEnv+"_ENTITY="+entity)
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
			o := commandsOptions(t, dir, "")
			if ev := evaluateOnly(t, o); ev.state != S1 {
				t.Fatalf("state after a crash in %s: %s", entity, ev.state)
			}
			assertNoGoDatabase(t, dir)
			st, err := startClosed(o)
			if err != nil || !st.Migrated {
				t.Fatalf("migration after the crash: %+v, %v", st, err)
			}
			m := openMigrated(t, dir, golden.manifest.SecretKey.Value, st.Report)
			var cmds, sets int
			_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
				if err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM commands_user`).Scan(&cmds); err != nil {
					return err
				}
				return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM commands_sets`).Scan(&sets)
			})
			if cmds != 2 || sets != 3 {
				t.Fatalf("%d commands and %d sets after the crash", cmds, sets)
			}
		})
	}
}
