package store_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

func TestSnapshotIsConsistentAndPrivate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	db, err := store.Open(t.Context(), filepath.Join(dir, "live.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		if _, err := tx.ExecContext(t.Context(), `CREATE TABLE t (v TEXT)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO t VALUES ('secret-row')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, "snap.db")
	if err := db.Snapshot(t.Context(), snap); err != nil {
		t.Fatal(err)
	}
	if err := db.Snapshot(t.Context(), snap); err == nil {
		t.Fatal("an existing snapshot was overwritten")
	}
	info, err := os.Stat(snap)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v, %v", info, err)
	}
	for _, s := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(snap + s); err == nil {
			t.Fatalf("side file %s beside the snapshot", s)
		}
	}
	copyDB, err := store.Open(t.Context(), snap, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := copyDB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM t`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := copyDB.Vacuum(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := copyDB.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(snap)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-row")) {
		t.Fatal("a deleted row survived the vacuum")
	}
}
