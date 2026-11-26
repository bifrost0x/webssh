package legacy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// Section 5.7: after activation a write by Python is seen by the next
// scan, an untouched source is not, and a link counts as a change.
func TestSourceWatch(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	if _, err := startClosed(testOptions(t, dir)); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), filepath.Join(dir, "go", "webssh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w, err := NewSourceWatch(t.Context(), db, dir)
	if err != nil || w == nil {
		t.Fatalf("watch: %v %v", w, err)
	}
	for range 2 {
		if changed, err := w.Changed(); changed || err != nil {
			t.Fatalf("untouched source: %v %v", changed, err)
		}
	}
	touchLegacy(t, dir)
	if changed, err := w.Changed(); !changed || err != nil {
		t.Fatalf("after a Python write: %v %v", changed, err)
	}

	linked := copyGolden(t)
	if _, err := startClosed(testOptions(t, linked)); err != nil {
		t.Fatal(err)
	}
	ldb, err := store.Open(t.Context(), filepath.Join(linked, "go", "webssh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer ldb.Close()
	lw, err := NewSourceWatch(t.Context(), ldb, linked)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("session_epoch", filepath.Join(linked, "planted-link")); err != nil {
		t.Fatal(err)
	}
	if changed, _ := lw.Changed(); !changed {
		t.Fatal("a link is not a change")
	}
}

// A Go-native installation has no record and nothing to watch.
func TestSourceWatchWithoutRecord(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, RecordSchema())
	w, err := NewSourceWatch(t.Context(), db, t.TempDir())
	if w != nil || err != nil {
		t.Fatalf("%v %v", w, err)
	}
}
