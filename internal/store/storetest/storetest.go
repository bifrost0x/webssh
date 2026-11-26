// Package storetest opens real, throw-away databases for tests of
// capability stores. Only test files import it (architecture tests).
package storetest

import (
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// Open returns a new database in a temporary directory with schemas
// applied. It is closed when the test ends.
func Open(t testing.TB, schemas ...store.Schema) *store.DB {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "webssh.db"), store.Options{})
	if err != nil {
		t.Fatalf("storetest: open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("storetest: close: %v", err)
		}
	})
	if err := db.ApplyAll(t.Context(), schemas...); err != nil {
		t.Fatalf("storetest: apply: %v", err)
	}
	return db
}
