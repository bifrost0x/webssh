package main

import "testing"

// helperTempDir points the TMPDIR of a helper process at a directory of
// the calling test. A helper killed with SIGKILL cannot remove its own
// temporary files; below the caller's t.TempDir they are removed with it.
func helperTempDir(t *testing.T) string {
	t.Helper()
	return "TMPDIR=" + t.TempDir()
}
