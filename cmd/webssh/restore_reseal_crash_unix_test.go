package main

import (
	"context"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/store"
)

// resealCrashEnv tells the helper process what to restore:
// "<archive>|<DATA_DIR>|<BACKUP_TEMP_DIR>".
const resealCrashEnv = "WEBSSH_RESEAL_CRASH"

// TestResealCrashHelper is the helper process of the crash test: it runs
// the steps of `webssh backup restore` and sends itself SIGKILL while the
// staged database is being resealed under the active SECRET_KEY.
func TestResealCrashHelper(t *testing.T) {
	spec := os.Getenv(resealCrashEnv)
	if spec == "" {
		t.Skip("helper process for the reseal crash test")
	}
	parts := strings.Split(spec, "|")
	t.Setenv("DATA_DIR", parts[1])
	t.Setenv("BACKUP_TEMP_DIR", parts[2])
	if err := os.Unsetenv("SECRET_KEY"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	o, err := migrationOptions(cfg, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	err = legacy.Exclusive(t.Context(), o, func(ctx context.Context) error {
		goDir := filepath.Join(cfg.DataDir, keyring.GoDirName)
		live, err := store.Open(ctx, filepath.Join(goDir, keyring.DatabaseName), store.Options{})
		if err != nil {
			return err
		}
		defer live.Close()
		in, err := cliInstallation(cfg, live, false)
		if err != nil {
			return err
		}
		in.Checkpoint = func(p string) {
			if p == backup.PointRestoreResealed {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		}
		if err := backup.Begin(goDir, "crash", time.Now()); err != nil {
			return err
		}
		_, err = backup.Stage(ctx, in, backup.StageRequest{OperationID: "crash", Archive: parts[0]})
		return err
	})
	t.Fatalf("no crash while resealing: %v", err)
}

// A SIGKILL while a Go archive of another SECRET_KEY is resealed beside
// legacy data changes nothing: the next start marks the restore failed
// and removes the staging, DATA_DIR/secret_key, the keyring material and
// every legacy file are unchanged, the state is S2, host B's secrets
// still open, and the restore then succeeds.
func TestResealCrash(t *testing.T) {
	archive, _, want := rotatedArchive(t)
	hostB := migratedBesideLegacy(t)
	secretB := readSecret(t, hostB)
	before := legacyOnly(t, hostB)
	materialPath, materialBefore, err := keyring.MaterialLocation(hostB, true)
	if err != nil {
		t.Fatal(err)
	}
	ownSecrets := secrets(t)
	names := storedUsernames(t)

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestResealCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), resealCrashEnv+"="+strings.Join([]string{archive, hostB, t.TempDir()}, "|"))
	cmd.Env = append(cmd.Env, helperTempDir(t)...)
	out, err := cmd.CombinedOutput()
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		t.Fatalf("helper did not fail: %v\n%s", err, out)
	}
	if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("helper ended without SIGKILL: %v\n%s", err, out)
	}

	if st := nextState(t); st != legacy.S2 {
		t.Fatalf("next start: %s, want S2", st)
	}
	j, err := backup.ReadJournal(filepath.Join(hostB, keyring.GoDirName))
	if err != nil || j == nil || j.State != backup.RestoreFailed {
		t.Fatalf("journal after the crash: %+v, %v", j, err)
	}
	entries, _ := os.ReadDir(filepath.Join(hostB, keyring.GoDirName))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".restore-") {
			t.Fatalf("staging left behind: %s", e.Name())
		}
	}
	if readSecret(t, hostB) != secretB {
		t.Fatal("DATA_DIR/secret_key changed")
	}
	if raw, err := os.ReadFile(materialPath); err != nil || string(raw) != string(materialBefore) { // #nosec G304 -- test data
		t.Fatalf("the keyring material changed: %v", err)
	}
	assertLegacyUnchanged(t, hostB, before)
	if got := secrets(t); !maps.Equal(got, ownSecrets) {
		t.Fatal("host B's secrets changed")
	}
	if got := storedUsernames(t); strings.Join(got, ",") != strings.Join(names, ",") {
		t.Fatalf("accounts after the crash: %v", got)
	}

	if out := runCLI(t, "backup", "restore", archive, "--confirm-offline"); out.Code != 0 {
		t.Fatalf("restore after the crash: %+v", out)
	}
	if got := secrets(t); !maps.Equal(got, want) || readSecret(t, hostB) != secretB {
		t.Fatal("the restore after the crash did not reseal the archive")
	}
	assertLegacyUnchanged(t, hostB, before)
}
