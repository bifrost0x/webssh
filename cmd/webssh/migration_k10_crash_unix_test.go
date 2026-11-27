package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/store"
)

const k10CrashEnv = "WEBSSH_K10_CRASH_IN"

// crashingStep kills the process with SIGKILL right after its step wrote
// into the staging transaction.
type crashingStep struct {
	legacy.Step
	target string
}

func (s crashingStep) Write(ctx context.Context, tx *store.Tx, seal legacy.Sealer) error {
	err := s.Step.Write(ctx, tx, seal)
	if s.Entity() == s.target {
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	}
	return err
}

// TestK10CrashHelper is the helper process of TestBuildCrashInEveryStep.
func TestK10CrashHelper(t *testing.T) {
	spec := os.Getenv(k10CrashEnv)
	if spec == "" {
		t.Skip("helper process for the K10 crash test")
	}
	entity, dir, _ := strings.Cut(spec, "|")
	_, lookup := k10Env(t, dir)
	cfg, err := bootstrapConfig(lookup, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	o, err := migrationOptions(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	o.Registry.WrapSteps(func(s legacy.Step) legacy.Step { return crashingStep{Step: s, target: entity} })
	st, err := legacy.Start(t.Context(), o)
	if err == nil {
		_ = st.Close()
	}
	t.Fatalf("no crash in %s: %v", entity, err)
}

// A SIGKILL inside any step of the build's complete registry leaves no
// partial state (spec 8.3): the legacy data is unchanged, the next start
// finds no Go database and migrates completely.
func TestBuildCrashInEveryStep(t *testing.T) {
	if testing.Short() {
		t.Skip("crash injection over every step")
	}
	_, lookup := k10Env(t, t.TempDir())
	cfg, err := bootstrapConfig(lookup, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := migrationRegistry(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	src := extractGolden(t, "datadir-extended.tar")
	for _, entity := range reg.StepEntities() {
		t.Run(entity, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "data")
			if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
				t.Fatal(err)
			}
			before := legacyState(t, dir)
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestK10CrashHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), k10CrashEnv+"="+entity+"|"+dir)
			cmd.Env = append(cmd.Env, helperTempDir(t))
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("helper did not fail: %v\n%s", err, out)
			}
			if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("helper ended without SIGKILL: %v\n%s", err, out)
			}
			assertLegacyUnchanged(t, dir, before)
			if _, err := os.Lstat(filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName)); err == nil {
				t.Fatal("a Go database exists after the crash")
			}
			_, lookup := k10Env(t, dir)
			log := slog.New(slog.DiscardHandler)
			cfg, err := bootstrapConfig(lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			st, err := startMigration(t.Context(), cfg, lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			if !st.Migrated || len(st.Report.Pending) != 0 {
				t.Fatalf("restart: state %s migrated=%v", st.State, st.Migrated)
			}
			assertLegacyUnchanged(t, dir, before)
		})
	}
}
