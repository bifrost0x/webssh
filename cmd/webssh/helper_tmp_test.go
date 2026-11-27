package main

import "testing"

// helperTempDir points the temporary directories of a helper process at a directory of
// the calling test. A helper killed with SIGKILL cannot remove its own
// temporary files; below the caller's t.TempDir they are removed with it.
func helperTempDir(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	// t.TempDir prefers GOTMPDIR, os.MkdirTemp uses TMPDIR: both point
	// at the caller's directory.
	return []string{"TMPDIR=" + dir, "GOTMPDIR=" + dir}
}
