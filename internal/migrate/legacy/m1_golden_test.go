package legacy

import (
	"testing"
)

func m1Options(t *testing.T, dataDir string, m M1) Options {
	t.Helper()
	r := NewRegistry()
	if err := RegisterM1(r, m); err != nil {
		t.Fatal(err)
	}
	o := testOptions(t, dataDir)
	o.Registry = r
	return o
}

func TestM1MigratesGolden(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	st, err := startClosed(m1Options(t, dir, M1{AdminUsers: []string{"cfg_admin"}}))
	if err != nil {
		t.Fatal(err)
	}
	assertUntouched(t, dir, before)
	for _, e := range st.Report.Entities {
		t.Logf("%s read=%d written=%d discarded=%d notes=%v flagged=%v warn=%v", e.Entity, e.Read, e.Written, e.Discarded, e.Notes, e.Flagged, e.Warnings)
	}
	t.Logf("pending %+v", st.Report.Pending)
}
