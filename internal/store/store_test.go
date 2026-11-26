package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

var hostsSchema = store.Schema{Owner: "hosts", Migrations: []store.Migration{
	{Version: 1, SQL: `CREATE TABLE hosts_profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE) STRICT`},
	{Version: 2, SQL: `CREATE TABLE hosts_tags (profile_id TEXT NOT NULL REFERENCES hosts_profiles(id), tag TEXT NOT NULL) STRICT`},
}}

func count(t *testing.T, db *store.DB, query string) int {
	t.Helper()
	var n int
	err := db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), query).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWriteCommitsAndRollsBack(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, hostsSchema)
	ctx := t.Context()
	insert := func(id string) func(*store.Tx) error {
		return func(tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO hosts_profiles (id, name) VALUES (?, ?)`, id, "n-"+id)
			return err
		}
	}
	if err := db.Write(ctx, insert("a")); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err := db.Write(ctx, func(tx *store.Tx) error {
		if err := insert("b")(tx); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Write returned %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM hosts_profiles`); n != 1 {
		t.Fatalf("%d rows, want 1 (rollback)", n)
	}
	err = db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO hosts_tags VALUES ('missing', 'x')`)
		return err
	})
	if err == nil {
		t.Fatal("foreign key not enforced")
	}
}

func TestReadIsReadOnly(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, hostsSchema)
	err := db.Read(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO hosts_profiles VALUES ('x', 'y')`)
		return err
	})
	if err == nil {
		t.Fatal("write inside Read succeeded")
	}
}

func TestParallelWriters(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, store.Schema{Owner: "settings", Migrations: []store.Migration{
		{Version: 1, SQL: `CREATE TABLE settings_counter (n INTEGER NOT NULL) STRICT; INSERT INTO settings_counter VALUES (0)`},
	}})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 10 {
				err := db.Write(t.Context(), func(tx *store.Tx) error {
					var n int
					if err := tx.QueryRowContext(t.Context(), `SELECT n FROM settings_counter`).Scan(&n); err != nil {
						return err
					}
					_, err := tx.ExecContext(t.Context(), `UPDATE settings_counter SET n = ?`, n+1)
					return err
				})
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if n := count(t, db, `SELECT n FROM settings_counter`); n != 160 {
		t.Fatalf("counter %d, want 160 (lost update)", n)
	}
}

func TestApply(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	tests := []struct {
		name   string
		base   []store.Schema
		schema store.Schema
	}{
		{name: "unknown owner", schema: store.Schema{Owner: "files", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE files_x (a)`}}}},
		{name: "gap", schema: store.Schema{Owner: "hosts", Migrations: []store.Migration{{Version: 2, SQL: `CREATE TABLE hosts_x (a)`}}}},
		{name: "empty", schema: store.Schema{Owner: "hosts", Migrations: []store.Migration{{Version: 1, SQL: " "}}}},
		{name: "foreign prefix", schema: store.Schema{Owner: "hosts", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE vault_keys (a)`}}}},
		{name: "unprefixed", schema: store.Schema{Owner: "hosts", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE profiles (a)`}}}},
		{name: "prefix without separator", schema: store.Schema{Owner: "auth", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE authlocal_x (a)`}}}},
		{name: "index on foreign table", base: []store.Schema{hostsSchema}, schema: store.Schema{Owner: "vault", Migrations: []store.Migration{{Version: 1, SQL: `CREATE UNIQUE INDEX vault_i ON hosts_profiles(id, name)`}}}},
		{name: "trigger on foreign table", base: []store.Schema{hostsSchema}, schema: store.Schema{Owner: "vault", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE vault_log (a); CREATE TRIGGER vault_t AFTER INSERT ON hosts_profiles BEGIN INSERT INTO vault_log VALUES (1); END`}}}},
		{name: "drop foreign table", base: []store.Schema{hostsSchema}, schema: store.Schema{Owner: "vault", Migrations: []store.Migration{{Version: 1, SQL: `DROP TABLE hosts_tags`}}}},
		{name: "syntax error", schema: store.Schema{Owner: "hosts", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE hosts_z (`}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := storetest.Open(t, tt.base...)
			const objects = `SELECT count(*) FROM sqlite_schema WHERE tbl_name <> 'store_migrations'`
			before := count(t, db, objects)
			if err := db.Apply(ctx, tt.schema.Owner, tt.schema.Migrations); err == nil {
				t.Fatal("migration accepted")
			}
			if n := count(t, db, objects); n != before {
				t.Fatalf("%d schema objects after a rejected migration, want %d", n, before)
			}
		})
	}
}

func TestApplyIsIdempotentAndDetectsEdits(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.Open(t, hostsSchema)
	if err := db.Apply(ctx, hostsSchema.Owner, hostsSchema.Migrations); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	edited := []store.Migration{hostsSchema.Migrations[0], {Version: 2, SQL: hostsSchema.Migrations[1].SQL + " "}}
	if err := db.Apply(ctx, "hosts", edited); !errors.Is(err, store.ErrMigration) {
		t.Fatalf("edited migration: %v", err)
	}
	if err := db.Apply(ctx, "hosts", hostsSchema.Migrations[:1]); !errors.Is(err, store.ErrMigration) {
		t.Fatalf("downgrade: %v", err)
	}
}

func TestOwnersDoNotOverlap(t *testing.T) {
	t.Parallel()
	for _, a := range store.Owners {
		for _, b := range store.Owners {
			if a != b && len(a) < len(b) && b[:len(a)+1] == a+"_" {
				t.Errorf("owner %q is a prefix of %q", a, b)
			}
		}
		for _, c := range a {
			if c < 'a' || c > 'z' {
				t.Errorf("owner %q has a character outside a-z", a)
			}
		}
	}
}

func TestCloseForActivation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "webssh.db")
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyAll(ctx, hostsSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Fatalf("database is not in WAL mode: %v", err)
	}
	if err := db.CloseForActivation(ctx); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind: %v", suffix, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("database mode %o, want 600", mode)
	}
	reopened, err := store.Open(context.WithoutCancel(ctx), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Apply(ctx, hostsSchema.Owner, hostsSchema.Migrations); err != nil {
		t.Fatalf("schema lost after activation: %v", err)
	}
}
