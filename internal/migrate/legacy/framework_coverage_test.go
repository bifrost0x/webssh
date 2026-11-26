package legacy

import (
	"os"
	"path/filepath"
	"testing"
)

// A build whose registry leaves entities uncovered must not migrate: the
// Go database would be activated without that data and S2 would never
// migrate it again. Nothing is written, and a fresh installation still
// starts.
func TestStartRefusesAnIncompleteBuild(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	o := testOptions(t, dir)
	o.RequireCoverage = true
	if len(o.Registry.Uncovered()) == 0 {
		t.Skip("the test registry covers every entity")
	}
	_, err := startClosed(o)
	if stopCode(err) != CodeIncompleteBuild {
		t.Fatalf("err = %v, want %s", err, CodeIncompleteBuild)
	}
	assertUntouched(t, dir, before)
	if _, err := os.Lstat(filepath.Join(dir, "go", "webssh.db")); err == nil {
		t.Fatal("a Go database was created")
	}

	fresh := testOptions(t, t.TempDir())
	fresh.RequireCoverage = true
	if st, err := startClosed(fresh); err != nil || st.State != S0 {
		t.Fatalf("fresh installation: %+v, %v", st, err)
	}
}
