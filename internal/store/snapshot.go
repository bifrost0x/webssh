package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Snapshot writes a consistent copy of the database to path while it is
// in use (VACUUM INTO, under the write lock, so that no write of this
// process is half in it). path must not exist; its directory must be
// private to the caller, because SQLite creates the file with the
// process umask before Snapshot narrows it to 0600. The copy is a
// complete database in journal_mode=DELETE without side files.
func (db *DB) Snapshot(ctx context.Context, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("store: resolve %q: %w", path, err)
	}
	if _, err := os.Lstat(abs); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: snapshot target %s exists", abs)
	}
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	if db.closed {
		return errClosed
	}
	if _, err := db.writer.ExecContext(ctx, "VACUUM INTO ?", abs); err != nil {
		return errors.Join(fmt.Errorf("store: snapshot: %w", err), removeIfPresent(abs))
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		return errors.Join(fmt.Errorf("store: snapshot: %w", err), removeIfPresent(abs))
	}
	return syncFile(abs)
}

// Vacuum rebuilds the database file, so that deleted rows leave no trace
// in free pages (an export removes remote credentials this way).
func (db *DB) Vacuum(ctx context.Context) error {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	if db.closed {
		return errClosed
	}
	if _, err := db.writer.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("store: vacuum: %w", err)
	}
	return db.narrowSideFiles()
}

func removeIfPresent(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
