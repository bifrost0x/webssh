package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
)

func newDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db with space ü.db")
	db, err := driver.Open("file:" + filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(t.Context(), "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x')"); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenReadOnlyReadsAndRefusesWrites(t *testing.T) {
	t.Parallel()
	for _, mode := range []ReadOnlyMode{Shared, Immutable} {
		path := newDatabase(t)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		db, err := OpenReadOnly(t.Context(), path, mode)
		if err != nil {
			t.Fatal(err)
		}
		var v string
		if err := db.QueryRowContext(t.Context(), "SELECT v FROM t").Scan(&v); err != nil || v != "x" {
			t.Fatalf("mode %d: read %q, %v", mode, v, err)
		}
		for _, stmt := range []string{"INSERT INTO t VALUES ('y')", "PRAGMA query_only = OFF; INSERT INTO t VALUES ('y')", "CREATE TABLE u (v)"} {
			if _, err := db.ExecContext(t.Context(), stmt); err == nil {
				t.Fatalf("mode %d: %q succeeded", mode, stmt)
			}
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(before) {
			t.Fatalf("mode %d: database file changed", mode)
		}
	}
}

func TestOpenReadOnlyDoesNotCreate(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing.db")
	if db, err := OpenReadOnly(t.Context(), path, Shared); err == nil {
		db.Close()
		t.Fatal("missing database opened")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file was created: %v", err)
	}
}

// Every connection, including ones database/sql opens later, carries the
// read-only pragmas.
func TestPragmasOnEveryConnection(t *testing.T) {
	t.Parallel()
	db, err := OpenReadOnly(t.Context(), newDatabase(t), Shared)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxIdleConns(0) // each query gets a new connection
	for range 3 {
		var queryOnly, trusted int
		if err := db.QueryRowContext(t.Context(), "SELECT (SELECT query_only FROM pragma_query_only), (SELECT trusted_schema FROM pragma_trusted_schema)").Scan(&queryOnly, &trusted); err != nil {
			t.Fatal(err)
		}
		if queryOnly != 1 || trusted != 0 {
			t.Fatalf("query_only=%d trusted_schema=%d", queryOnly, trusted)
		}
	}
}

// hardenConnection turns off a trusted schema that was on, and fails
// closed when a pragma does not hold.
func TestHardenConnectionOverridesTrustedSchema(t *testing.T) {
	t.Parallel()
	path := newDatabase(t)
	var trusted, queryOnly int
	db, err := driver.Open("file:"+filepath.ToSlash(path)+"?mode=ro", func(c *sqlite3.Conn) error {
		if err := c.Exec("PRAGMA trusted_schema = ON"); err != nil {
			return err
		}
		return hardenConnection(c)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRowContext(t.Context(), "SELECT (SELECT trusted_schema FROM pragma_trusted_schema), (SELECT query_only FROM pragma_query_only)").Scan(&trusted, &queryOnly); err != nil {
		t.Fatal(err)
	}
	if trusted != 0 || queryOnly != 1 {
		t.Fatalf("trusted_schema=%d query_only=%d", trusted, queryOnly)
	}
}
