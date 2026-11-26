package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
)

// Options configure Open. The zero value is valid.
type Options struct {
	// BusyTimeout bounds how long a statement waits for a lock held by
	// another connection (default 5 s).
	BusyTimeout time.Duration
	// MaxReaders bounds concurrent read transactions (default 4).
	MaxReaders int
}

// DB is WebSSH's own database. Writes are serialized in the process and
// run on one connection; reads run concurrently on read-only connections
// and see the last committed state (WAL).
type DB struct {
	path   string
	writer *sql.DB
	reader *sql.DB
	// writeMu serializes write transactions inside the process, so a
	// writer never waits on SQLite's busy handler for another goroutine.
	writeMu sync.Mutex
}

// Tx is a transaction handed to Read and Write callbacks. It is valid only
// during the callback; the store commits or rolls back, never the caller.
type Tx struct {
	tx *sql.Tx
}

// ExecContext runs a statement that returns no rows.
func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, query, args...)
}

// QueryContext runs a query. The caller closes the rows before the
// callback returns.
func (t *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, query, args...)
}

// QueryRowContext runs a query that returns at most one row.
func (t *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(ctx, query, args...)
}

// writerPragmas are set on the write connection and read back.
// trusted_schema = OFF keeps functions with side effects out of views and
// triggers; foreign_keys enforces the references every capability
// declares.
var writerPragmas = []struct {
	set, get string
	want     int64
}{
	{"PRAGMA foreign_keys = ON", "PRAGMA foreign_keys", 1},
	{"PRAGMA trusted_schema = OFF", "PRAGMA trusted_schema", 0},
	{"PRAGMA synchronous = FULL", "PRAGMA synchronous", 2},
}

func hardenWriter(busy time.Duration) func(*sqlite3.Conn) error {
	return func(c *sqlite3.Conn) error {
		if err := c.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", busy.Milliseconds())); err != nil {
			return fmt.Errorf("store: busy_timeout: %w", err)
		}
		for _, p := range writerPragmas {
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
}

func hardenReader(busy time.Duration) func(*sqlite3.Conn) error {
	return func(c *sqlite3.Conn) error {
		if err := c.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", busy.Milliseconds())); err != nil {
			return fmt.Errorf("store: busy_timeout: %w", err)
		}
		return hardenConnection(c)
	}
}

// Open opens or creates the database at path in WAL mode. A new file is
// created with mode 0600. The caller closes the DB.
func Open(ctx context.Context, path string, o Options) (*DB, error) {
	if o.BusyTimeout <= 0 {
		o.BusyTimeout = 5 * time.Second
	}
	if o.MaxReaders <= 0 {
		o.MaxReaders = 4
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: resolve %q: %w", path, err)
	}
	// Create the file with restrictive permissions before SQLite does.
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- the configured database path, not request input
	if err != nil {
		return nil, fmt.Errorf("store: create database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("store: create database: %w", err)
	}
	dsn := func(mode string) string {
		q := url.Values{"mode": {mode}, "_txlock": {"immediate"}}
		return (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: q.Encode()}).String()
	}
	writer, err := driver.Open(dsn("rw"), hardenWriter(o.BusyTimeout))
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	writer.SetMaxOpenConns(1)
	db := &DB{path: abs, writer: writer}
	if err := db.setJournalMode(ctx, "wal"); err != nil {
		return nil, errors.Join(err, writer.Close())
	}
	reader, err := driver.Open(dsn("ro"), hardenReader(o.BusyTimeout))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("store: open database: %w", err), writer.Close())
	}
	reader.SetMaxOpenConns(o.MaxReaders)
	db.reader = reader
	if err := reader.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("store: open database: %w", err), db.Close())
	}
	return db, nil
}

func (db *DB) setJournalMode(ctx context.Context, mode string) error {
	var got string
	if err := db.writer.QueryRowContext(ctx, "PRAGMA journal_mode = "+mode).Scan(&got); err != nil {
		return fmt.Errorf("store: journal_mode %s: %w", mode, err)
	}
	if got != mode {
		return fmt.Errorf("%w: journal_mode = %s, want %s", errPragma, got, mode)
	}
	return nil
}

// Path returns the absolute path of the database file.
func (db *DB) Path() string { return db.path }

// Write runs fn in a write transaction. Write transactions are serialized;
// fn's changes are committed if it returns nil and rolled back otherwise.
// fn must not call Read or Write.
func (db *DB) Write(ctx context.Context, fn func(*Tx) error) error {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	return run(ctx, db.writer, nil, fn)
}

// Read runs fn in a read-only transaction with a consistent snapshot.
func (db *DB) Read(ctx context.Context, fn func(*Tx) error) error {
	return run(ctx, db.reader, &sql.TxOptions{ReadOnly: true}, fn)
}

func run(ctx context.Context, pool *sql.DB, opts *sql.TxOptions, fn func(*Tx) error) error {
	tx, err := pool.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(&Tx{tx: tx}); err != nil {
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			return errors.Join(err, fmt.Errorf("store: rollback: %w", rerr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// Close closes all connections. The WAL stays in place; use
// CloseForActivation to leave a single file.
func (db *DB) Close() error {
	var errs []error
	if db.reader != nil {
		errs = append(errs, db.reader.Close())
	}
	errs = append(errs, db.writer.Close())
	return errors.Join(errs...)
}

// CloseForActivation checkpoints the WAL, switches the database to
// journal_mode=DELETE and closes it, so that only the database file
// remains (no -wal or -shm). The migration calls it before it moves a
// staged database into place (migration spec, section 5.2).
func (db *DB) CloseForActivation(ctx context.Context) error {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	if err := db.reader.Close(); err != nil {
		return errors.Join(fmt.Errorf("store: close readers: %w", err), db.writer.Close())
	}
	db.reader = nil
	if _, err := db.writer.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return errors.Join(fmt.Errorf("store: checkpoint: %w", err), db.writer.Close())
	}
	if err := db.setJournalMode(ctx, "delete"); err != nil {
		return errors.Join(err, db.writer.Close())
	}
	if err := db.writer.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(db.path + suffix); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("store: %s still present after activation close (%v)", suffix, err)
		}
	}
	return nil
}
