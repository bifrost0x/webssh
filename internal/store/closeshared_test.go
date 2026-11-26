package store_test

import (
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// A second user of the database (an administrator command beside the
// running server) closes without the journal switch: Close would fail
// with "database is locked" while the owner holds it, CloseShared does
// not, and the owner still leaves one file when it stops.
func TestCloseSharedBesideTheOwner(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "webssh.db")
	owner := openHosts(t, path)
	insertProfile(t, owner, "a")
	guest := openHosts(t, path)
	insertProfile(t, guest, "b")
	if err := guest.CloseShared(); err != nil {
		t.Fatalf("CloseShared: %v", err)
	}
	if err := guest.CloseShared(); err != nil {
		t.Fatalf("second CloseShared: %v", err)
	}
	if err := guest.Write(t.Context(), func(*store.Tx) error { return nil }); err == nil {
		t.Fatal("Write after CloseShared succeeded")
	}
	insertProfile(t, owner, "c")
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if left := sideFiles(t, path); len(left) != 0 {
		t.Fatalf("side files after the owner closed: %v", left)
	}
}
