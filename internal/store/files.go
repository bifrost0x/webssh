package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotRegular reports a database path that is not a regular file, or
// whose directory is not a plain directory.
var ErrNotRegular = errors.New("store: database path is not a regular file in a directory")

var errClosed = errors.New("store: database is closed")

// createRegular creates the database file with mode 0600 unless it exists,
// and refuses symlinks and other non-regular entries for the file and its
// directory. SQLite would follow a symlink, and Python 3.3.x aborts a
// backup or restore on one.
func createRegular(path string) error {
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("store: database directory: %w", err)
	}
	if !dir.IsDir() {
		return fmt.Errorf("%w: %s", ErrNotRegular, filepath.Dir(path))
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil && !info.Mode().IsRegular():
		return fmt.Errorf("%w: %s", ErrNotRegular, path)
	case err == nil:
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("store: database: %w", err)
	}
	// O_EXCL: a symlink created in between is not followed.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the configured database path, not request input
	if err != nil {
		return fmt.Errorf("store: create database: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: create database: %w", err)
	}
	return nil
}

// syncFile fsyncs a closed file so that its content is durable before the
// caller renames it.
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- the database path the store opened
	if err != nil {
		return fmt.Errorf("store: sync database: %w", err)
	}
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(serr, cerr); err != nil {
		return fmt.Errorf("store: sync database: %w", err)
	}
	return nil
}
