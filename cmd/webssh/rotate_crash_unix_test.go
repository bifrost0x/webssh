package main

import (
	"errors"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
)

// rotationCrashEnv tells the helper process where to kill itself:
// "<point>|<DATA_DIR>|<BACKUP_TEMP_DIR>".
const rotationCrashEnv = "WEBSSH_ROTATION_CRASH_AT"

// TestRotationCrashHelper is the helper process of the crash test: it
// rotates and sends itself SIGKILL at the named checkpoint.
func TestRotationCrashHelper(t *testing.T) {
	spec := os.Getenv(rotationCrashEnv)
	if spec == "" {
		t.Skip("helper process for the rotation crash test")
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
	r := &secretRotator{cfg: cfg, checkpoint: func(p string) {
		if p == parts[0] {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	}}
	_, err = r.Rotate(t.Context())
	t.Fatalf("no crash at %s: %v", parts[0], err)
}

var rotationPoints = []string{backup.PointPrepared, backup.PointPending, backup.PointResealed, backup.PointCommitted,
	backup.PointInstalled, backup.PointDone}

// A SIGKILL at every step of the rotation loses nothing: the next start
// (which reads the configuration first) finds SECRET_KEY and the database
// in agreement, every secret opens to its plaintext, no pending secret is
// left once a start or a rotation ran, and a new rotation succeeds.
func TestRotationCrash(t *testing.T) {
	// The migration of the golden data set is the slow part; it runs once
	// and every point starts from a copy.
	base := migratedPurged(t)
	for _, point := range rotationPoints {
		t.Run(point, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			copyTree(t, base, dir)
			rotationEnv(t, dir)
			before := secrets(t)
			oldSecret := readSecret(t, dir)
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRotationCrashHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), rotationCrashEnv+"="+strings.Join([]string{point, dir, t.TempDir()}, "|"))
			out, err := cmd.CombinedOutput()
			exit, ok := errors.AsType[*exec.ExitError](err)
			if !ok {
				t.Fatalf("helper did not fail: %v\n%s", err, out)
			}
			if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("helper ended without SIGKILL: %v\n%s", err, out)
			}
			committed := slices.Index(rotationPoints, point) >= slices.Index(rotationPoints, backup.PointCommitted)
			if point == backup.PointCommitted {
				// The server start completes the rotation as well.
				if _, err := bootstrapConfig(os.LookupEnv, slog.New(slog.DiscardHandler)); err != nil {
					t.Fatal(err)
				}
				if readSecret(t, dir) == oldSecret {
					t.Fatal("the server start did not install the committed secret")
				}
			}
			if after := secrets(t); !maps.Equal(after, before) {
				t.Fatalf("secrets differ after a crash at %s", point)
			}
			if changed := readSecret(t, dir) != oldSecret; changed != committed {
				t.Fatalf("crash at %s: secret changed %t, committed %t", point, changed, committed)
			}
			pending := filepath.Join(dir, keyring.GoDirName, backup.PendingSecretName)
			_, perr := os.Lstat(pending)
			if committed && !os.IsNotExist(perr) {
				t.Fatalf("crash at %s: the start left the pending secret: %v", point, perr)
			}
			if res := runCLI(t, "rotate-secret-key", "--confirm-offline"); res.Code != 0 {
				t.Fatalf("rotation after a crash at %s: %+v", point, res)
			}
			if after := secrets(t); !maps.Equal(after, before) {
				t.Fatalf("secrets differ after the rotation that followed a crash at %s", point)
			}
			if _, err := os.Lstat(pending); !os.IsNotExist(err) {
				t.Fatalf("pending secret after the next rotation: %v", err)
			}
		})
	}
}

// copyTree copies a data directory with its file modes (the keyring
// material must stay 0600).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- test data
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}
