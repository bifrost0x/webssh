package store_test

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// TestStatementAfterImplicitRollback checks that a write transaction that
// SQLite rolled back on its own (here through INSERT OR ROLLBACK, as also
// after an interrupt, a full disk or an I/O error) commits nothing, even
// if the callback ignores the error and goes on. Before go-sqlite3 v0.38.1
// the later statements ran in autocommit mode and were stored.
func TestStatementAfterImplicitRollback(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, hostsSchema)
	ctx := t.Context()
	if err := db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO hosts_profiles VALUES ('a', 'taken')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := db.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hosts_profiles VALUES ('b', 'first')`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR ROLLBACK INTO hosts_profiles VALUES ('c', 'taken')`); err == nil {
			t.Error("conflict not reported")
		}
		_, _ = tx.ExecContext(ctx, `INSERT INTO hosts_profiles VALUES ('d', 'after')`)
		return nil
	})
	if err == nil {
		t.Error("Write reported success for a rolled-back transaction")
	}
	if n := count(t, db, `SELECT count(*) FROM hosts_profiles`); n != 1 {
		t.Fatalf("%d rows, want 1: statements after the rollback were stored", n)
	}
}
