package legacy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const tempHelperEnv = "WEBSSH_TEMP_HELPER"

// helperTempDir points the temporary directories of a helper process at a directory of
// the calling test. A helper killed with SIGKILL cannot remove its own
// temporary files (t.TempDir, os.MkdirTemp, the fixture TestMain
// unpacks); below the caller's t.TempDir they are removed with it.
func helperTempDir(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	// t.TempDir prefers GOTMPDIR, os.MkdirTemp uses TMPDIR: both point
	// at the caller's directory.
	return []string{"TMPDIR=" + dir, "GOTMPDIR=" + dir}
}

// TestTempHelper is the helper of TestKilledHelperLeavesNothingBehind: it
// reports where its temporary files went and kills itself.
func TestTempHelper(t *testing.T) {
	if os.Getenv(tempHelperEnv) == "" {
		t.Skip("helper process for the temporary file test")
	}
	fmt.Printf("TEMP %s\nTEMP %s\n", golden.root, t.TempDir())
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}

// A helper killed with SIGKILL, as in every crash test, leaves its
// temporary files (the unpacked fixture and its t.TempDir) only below the
// directory the calling test passed, so nothing remains outside the
// caller's t.TempDir.
func TestKilledHelperLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTempHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), tempHelperEnv+"=1")
	tmp := helperTempDir(t)
	cmd.Env = append(cmd.Env, tmp...)
	out, err := cmd.Output()
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Fatalf("helper did not die: %v\n%s", err, out)
	}
	dir := strings.TrimPrefix(tmp[0], "TMPDIR=")
	var paths []string
	for line := range strings.Lines(string(out)) {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "TEMP "); ok {
			paths = append(paths, p)
		}
	}
	if len(paths) != 2 {
		t.Fatalf("helper output %q", out)
	}
	for _, p := range paths {
		rel, err := filepath.Rel(dir, p)
		if err != nil || !filepath.IsLocal(rel) {
			t.Errorf("helper temporary path %s outside %s", p, dir)
		}
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("helper path %s not created: %v", p, err)
		}
	}
}
