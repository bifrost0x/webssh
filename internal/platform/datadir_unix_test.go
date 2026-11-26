//go:build unix

package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode %04o, want %04o", path, got, want)
	}
}

func TestPrepareDataDirCreatesOwnerOnlyTree(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "nested", "data")
	root, err := PrepareDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{root, filepath.Join(root, "logs"), filepath.Join(root, "keys")} {
		assertMode(t, p, 0o700)
	}
	leftovers, err := filepath.Glob(filepath.Join(root, probePrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Errorf("probe files left behind: %v", leftovers)
	}
}

func TestPrepareDataDirNarrowsWidenedModes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, keys} {
		if err := os.Chmod(p, 0o777); err != nil { // #nosec G302 -- the test widens on purpose
			t.Fatal(err)
		}
	}
	if _, err := PrepareDataDir(dir); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, keys} {
		assertMode(t, p, 0o700)
	}
}

func TestPrepareDataDirKeepsExistingFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "webssh.db")
	if err := os.WriteFile(file, []byte("legacy"), 0o644); err != nil { // #nosec G306 -- the test checks the mode stays as it is
		t.Fatal(err)
	}
	if _, err := PrepareDataDir(dir); err != nil {
		t.Fatal(err)
	}
	assertMode(t, file, 0o644)
	data, err := os.ReadFile(file) // #nosec G304 -- test file in a temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "legacy" {
		t.Errorf("content changed to %q", data)
	}
}

func TestPrepareDataDirResolvesSymlinks(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	root, err := PrepareDataDir(link)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if root != want {
		t.Errorf("root %q, want %q", root, want)
	}
}

func TestPrepareDataDirExplainsUnwritableParent(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) })
	_, err := PrepareDataDir(filepath.Join(base, "data"))
	dirErr, ok := errors.AsType[*DataDirError](err)
	if !ok {
		t.Fatalf("err %v, want *DataDirError", err)
	}
	id := fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())
	if !strings.Contains(dirErr.Error(), "chown -R "+id+" <host directory>") {
		t.Errorf("error %q lacks the chown hint for %s", dirErr, id)
	}
}

func TestPrepareDataDirFailsWhenSubdirIsAFile(t *testing.T) {
	t.Parallel()
	// The start must fail instead of continuing without the logs directory.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "logs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareDataDir(dir); err == nil {
		t.Fatal("want an error when logs is a file")
	}
	assertMode(t, filepath.Join(dir, "logs"), 0o600)
}

func TestProbeDataDirFailsOnMissingDirectory(t *testing.T) {
	t.Parallel()
	if err := ProbeDataDir(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("want an error for a missing directory")
	}
}

func TestDescribeDataDir(t *testing.T) {
	t.Parallel()
	root, err := PrepareDataDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	desc, err := DescribeDataDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := "mode=0700 runtime_user=" + RuntimeIdentity(); desc != want {
		t.Errorf("describe %q, want %q", desc, want)
	}
}
