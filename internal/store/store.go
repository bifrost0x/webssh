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
	// readMu is held shared by every running Read and exclusively by
	// Close, so Close waits for running reads before it checkpoints.
	readMu sync.RWMutex
	// closed is set with writeMu and readMu held, so either suffices to
	// read it.
	closed bool
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
// created with mode 0600. path must be a regular file, or missing, in a
// directory reached without a symlink in its last component: the Go
// directory holds only regular files and directories (migration
// specification, 2.1). The caller closes the DB.
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
	before, err := createRegular(abs)
	if err != nil {
		return nil, err
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
	// SQLite follows symlinks: make sure it opened the file checked above.
	if err := sameRegular(abs, before); err != nil {
		return nil, errors.Join(err, db.Close())
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
	if db.closed {
		return errClosed
	}
	return run(ctx, db.writer, nil, fn)
}

// Read runs fn in a read-only transaction with a consistent snapshot.
func (db *DB) Read(ctx context.Context, fn func(*Tx) error) error {
	db.readMu.RLock()
	defer db.readMu.RUnlock()
	if db.closed {
		return errClosed
	}
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

// Close switches the database to journal_mode=DELETE and closes all
// connections, so that a stopped Go leaves only the database file: a copy
// that Python 3.3.x or an operator takes of the Go directory then is a
// complete database (migration specification, 2.1). It waits for a
// running write and for running reads. If the switch fails the connections are still closed and
// the error is returned; SQLite recovers the WAL at the next Open.
func (db *DB) Close() error {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	return db.closeLocked(context.Background())
}

func (db *DB) closeLocked(ctx context.Context) error {
	db.readMu.Lock()
	defer db.readMu.Unlock()
	if db.closed {
		return nil
	}
	db.closed = true
	var errs []error
	if db.reader != nil {
		if err := db.reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("store: close readers: %w", err))
		}
	}
	if len(errs) == 0 {
		// The checkpoint and the mode switch need the readers closed.
		if err := db.checkpoint(ctx); err != nil {
			errs = append(errs, err)
		} else if err := db.setJournalMode(ctx, "delete"); err != nil {
			errs = append(errs, err)
		}
	}
	if err := db.writer.Close(); err != nil {
		errs = append(errs, fmt.Errorf("store: close: %w", err))
	}
	return errors.Join(errs...)
}

// CloseForActivation closes the database like Close and then checks that
// no -wal, -shm or -journal file is left beside it and fsyncs the file.
// The migration calls it before it moves a staged database into place
// (migration specification, 5.2 step 10).
func (db *DB) CloseForActivation(ctx context.Context) error {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	db.readMu.RLock()
	closed := db.closed
	db.readMu.RUnlock()
	if closed {
		return errClosed
	}
	if err := db.closeLocked(ctx); err != nil {
		return err
	}
	afterActivationClose(db.path)
	if err := onlyDatabaseFile(db.path); err != nil {
		return err
	}
	return syncFile(db.path)
}

// afterActivationClose runs between the close and the side-file check of
// CloseForActivation. SQLite removes the side files a test could plant
// before the close, so only this seam lets a test reach the check.
var afterActivationClose = func(string) {}

// onlyDatabaseFile fails when a -wal, -shm or -journal entry exists beside
// the database. SQLite removes its own on a clean close in
// journal_mode=DELETE; one that is still there belongs to another writer
// or a crash and would be moved together with the database.
func onlyDatabaseFile(path string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("store: %s still present after activation close (%v)", suffix, err)
		}
	}
	return nil
}

// checkpoint copies the WAL into the database and truncates it. A
// checkpoint that a reader or writer blocked reports busy.
func (db *DB) checkpoint(ctx context.Context) error {
	var busy, logFrames, done int64
	if err := db.writer.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &done); err != nil {
		return fmt.Errorf("store: checkpoint: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("store: checkpoint blocked (%d of %d frames copied)", done, logFrames)
	}
	return nil
}
