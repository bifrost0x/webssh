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
// and refuses symlinks and other non-regular entries for the file, its
// side files and its directory. SQLite would follow a symlink, and Python
// 3.3.x aborts a backup or restore on one. It returns the file it checked.
func createRegular(path string) (fs.FileInfo, error) {
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("store: database directory: %w", err)
	}
	if !dir.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, filepath.Dir(path))
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		info, err := os.Lstat(path + suffix)
		if err == nil && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s", ErrNotRegular, path+suffix)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("store: database: %w", err)
		}
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil && !info.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, path)
	case err == nil:
		return info, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("store: database: %w", err)
	}
	// O_EXCL: a symlink created in between is not followed.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the configured database path, not request input
	if err != nil {
		return nil, fmt.Errorf("store: create database: %w", err)
	}
	info, err = f.Stat()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("store: create database: %w", err)
	}
	return info, nil
}

// sameRegular checks that path is still the regular file checked before.
func sameRegular(path string, before fs.FileInfo) error {
	now, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("store: database: %w", err)
	}
	if !now.Mode().IsRegular() || !os.SameFile(before, now) {
		return fmt.Errorf("%w: %s was replaced while it was opened", ErrNotRegular, path)
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
