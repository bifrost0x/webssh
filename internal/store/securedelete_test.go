package store_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// Deleted rows are overwritten (secure_delete): a removed sealed secret
// must not stay readable in free pages of the file, which raw copies of
// the database (purge and pre-rotation archives) would carry along.
func TestDeletedRowsLeaveNoTrace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "webssh.db")
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	schema := store.Schema{Owner: "vault", Migrations: []store.Migration{
		{Version: 1, SQL: `CREATE TABLE vault_secrets (id INTEGER PRIMARY KEY, sealed BLOB NOT NULL) STRICT`},
	}}
	if err := db.ApplyAll(ctx, schema); err != nil {
		t.Fatal(err)
	}
	marker := bytes.Repeat([]byte("SEALED-SECRET-MARKER"), 400)
	if err := db.Write(ctx, func(tx *store.Tx) error {
		for i := range 4 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO vault_secrets (id, sealed) VALUES (?, ?)`, i, marker); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM vault_secrets`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("SEALED-SECRET-MARKER")) {
		t.Fatal("a deleted value is still in the database file")
	}
}
