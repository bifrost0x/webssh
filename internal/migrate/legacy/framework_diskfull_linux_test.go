package legacy

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// diskFullEnv makes TestDiskFullHelper run: "<DATA_DIR>|<bypass>".
const diskFullEnv = "WEBSSH_MIGRATION_DISK_FULL"

// TestDiskFullHelper runs inside a user and mount namespace in which go/
// is a tiny tmpfs. With bypass set, the space check is skipped, so the
// staging writes hit ENOSPC; otherwise the check must refuse up front.
func TestDiskFullHelper(t *testing.T) {
	spec := os.Getenv(diskFullEnv)
	if spec == "" {
		t.Skip("helper process for the disk-full test")
	}
	dir, bypass, _ := strings.Cut(spec, "|")
	o := testOptions(t, dir)
	if bypass == "bypass" {
		o.freeSpace = func(string) (uint64, error) { return math.MaxUint64, nil }
	}
	_, err := startClosed(o)
	switch {
	case bypass != "bypass" && stopCode(err) != CodeNoSpace:
		t.Fatalf("space check: %v", err)
	case bypass == "bypass" && (err == nil || !strings.Contains(err.Error(), "no space left") && !strings.Contains(err.Error(), "disk is full")):
		t.Fatalf("ENOSPC: %v", err)
	}
	l := mustLayout(t, dir)
	if dirs, _ := l.stagingDirs(); len(dirs) != 0 {
		t.Fatalf("staging left after ENOSPC: %v", dirs)
	}
	if ok, _ := l.databasePresent(); ok {
		t.Fatal("a database was activated")
	}
	fmt.Println("DISKFULL-OK", err)
}

// Section 8.3 "full disk" on a size-limited file system for the Go
// directory: the space check refuses up front, and with the check bypassed
// ENOSPC during the staging writes is STOP with clean-up.
func TestDiskFull(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	for _, mode := range []string{"check", "bypass"} {
		dir := copyGolden(t)
		goDir := filepath.Join(dir, "go")
		if err := os.Mkdir(goDir, 0o700); err != nil {
			t.Fatal(err)
		}
		before := legacySnapshot(t, dir)
		cmd := exec.CommandContext(t.Context(), "unshare", "--user", "--map-root-user", "--mount", "sh", "-c",
			`mount -t tmpfs -o size=96k tmpfs "$1" && exec "$2" -test.run='^TestDiskFullHelper$' -test.count=1 -test.v`,
			"sh", goDir, os.Args[0])
		cmd.Env = append(os.Environ(), diskFullEnv+"="+dir+"|"+mode)
		cmd.Env = append(cmd.Env, helperTempDir(t)...)
		out, err := cmd.CombinedOutput()
		if strings.Contains(string(out), "mount:") || strings.Contains(string(out), "unshare:") {
			t.Skipf("no rootless tmpfs here: %s", out)
		}
		if err != nil || !strings.Contains(string(out), "DISKFULL-OK") {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		assertUntouched(t, dir, before)
	}
}
