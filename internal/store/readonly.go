// Package store owns WebSSH's access to SQLite. It is the only package that
// uses the SQLite driver.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
)

// ReadOnlyMode selects how a foreign database is opened for reading.
type ReadOnlyMode int

const (
	// Shared opens the database read-only with normal SQLite locking, so a
	// concurrent writer is noticed instead of being read past. A database
	// in WAL mode must not be opened this way: SQLite would create the
	// -wal and -shm files beside it.
	Shared ReadOnlyMode = iota
	// Immutable additionally tells SQLite that no one else can change the
	// file, so it takes no locks and creates no side files. Use it for
	// private copies, and for a source whose journal the caller has
	// checked to be empty.
	Immutable
)

// readOnlyPragmas are set on every connection and read back. query_only
// refuses every write even if a statement slips through; trusted_schema
// = OFF keeps functions with side effects from running out of views,
// triggers or generated columns of a database that came from outside.
// The bundled SQLite already defaults to trusted_schema = OFF; setting it
// keeps that true if the build default changes.
var readOnlyPragmas = []struct {
	set, get string
	want     int64
}{
	{"PRAGMA query_only = ON", "PRAGMA query_only", 1},
	{"PRAGMA trusted_schema = OFF", "PRAGMA trusted_schema", 0},
}

// errPragma reports a connection on which a read-only pragma did not take
// effect. OpenReadOnly fails closed on it.
var errPragma = errors.New("store: read-only pragma not in effect")

// hardenConnection runs on every new connection, so a connection that
// database/sql opens later (for example after a bad connection) is just
// as restricted as the first one.
func hardenConnection(c *sqlite3.Conn) error {
	for _, p := range readOnlyPragmas {
		if err := c.Exec(p.set); err != nil {
			return fmt.Errorf("store: %s: %w", p.set, err)
		}
		got, err := pragmaValue(c, p.get)
		if err != nil {
			return err
		}
		if got != p.want {
			return fmt.Errorf("%w: %s = %d", errPragma, p.get, got)
		}
	}
	return nil
}

func pragmaValue(c *sqlite3.Conn, query string) (int64, error) {
	stmt, _, err := c.Prepare(query)
	if err != nil {
		return 0, fmt.Errorf("store: %s: %w", query, err)
	}
	defer stmt.Close()
	if !stmt.Step() {
		if err := stmt.Err(); err != nil {
			return 0, fmt.Errorf("store: %s: %w", query, err)
		}
		return 0, fmt.Errorf("%w: %s returned no row", errPragma, query)
	}
	return stmt.ColumnInt64(0), nil
}

// OpenReadOnly opens an existing SQLite database without the ability to
// change it: the file is opened with mode=ro and every connection runs with
// query_only and trusted_schema = OFF, checked after setting them. The
// database must exist; it is never created. The caller closes the handle.
func OpenReadOnly(ctx context.Context, path string, mode ReadOnlyMode) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: resolve %q: %w", path, err)
	}
	query := url.Values{"mode": {"ro"}}
	if mode == Immutable {
		query.Set("immutable", "1")
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: query.Encode()}).String()
	db, err := driver.Open(dsn, hardenConnection)
	if err != nil {
		return nil, fmt.Errorf("store: open read-only database: %w", err)
	}
	db.SetMaxOpenConns(1)
	// The driver opens connections lazily; open one now so that a missing
	// file or a failed pragma is reported here.
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("store: open read-only database: %w", err), db.Close())
	}
	return db, nil
}
