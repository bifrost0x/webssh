package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrMaterialFile reports a material path that is not a regular file of
// the right size, or a Go directory that is not a plain directory. The Go
// directory holds only regular files and directories, because Python 3.3.x
// aborts a backup or restore on anything else (migration spec, 2.1).
var ErrMaterialFile = errors.New("keyring: keyring material file is not usable")

// readMaterial reads a material file without following a symlink. A
// missing file returns (nil, nil).
func readMaterial(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keyring: %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrMaterialFile, path)
	}
	f, err := os.Open(path) // #nosec G304 -- a fixed name below the configured DATA_DIR
	if err != nil {
		return nil, fmt.Errorf("keyring: %s: %w", path, err)
	}
	defer f.Close()
	// The file opened must be the one checked, not a symlink swapped in.
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("keyring: %s: %w", path, err)
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%w: %s changed while it was opened", ErrMaterialFile, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaterialSize+1))
	if err != nil {
		return nil, fmt.Errorf("keyring: %s: %w", path, err)
	}
	if len(data) != MaterialSize {
		return nil, fmt.Errorf("%w: %s has %d bytes, want %d", ErrMaterialFile, path, len(data), MaterialSize)
	}
	return data, nil
}

// ensureDir creates dir with mode 0700 if it is missing and checks that it
// is a directory, not a symlink.
func ensureDir(dir string) error {
	err := os.Mkdir(dir, 0o700)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("keyring: create %s: %w", dir, err)
	}
	return checkDir(dir)
}

// checkDir fails unless dir is a directory reached without a symlink in
// its last component. A missing directory is not an error.
func checkDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("keyring: %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrMaterialFile, dir)
	}
	return nil
}

// exists reports whether anything (file, directory or symlink) is at path.
func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("keyring: %s: %w", path, err)
	}
}

// removeFile removes a regular file; a missing file is not an error.
func removeFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("keyring: %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrMaterialFile, path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("keyring: remove %s: %w", path, err)
	}
	return syncDir(filepath.Dir(path))
}

// writeFileSynced writes data to path (which must not exist) with mode
// 0600, fsyncs it and reads it back.
func writeFileSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a fixed name below the configured DATA_DIR
	if err != nil {
		return fmt.Errorf("keyring: create %s: %w", path, err)
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("keyring: write %s: %w", path, err)
	}
	back, err := readMaterial(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(back, data) {
		return fmt.Errorf("%w: %s reads back differently", ErrMaterialFile, path)
	}
	return nil
}

// installFile writes data to a temporary file in the target directory and
// renames it to path, so that path holds either nothing or the complete
// file. The directory is fsynced afterwards.
func installFile(tmp, path string, data []byte) error {
	if err := removeFile(tmp); err != nil {
		return err
	}
	if err := writeFileSynced(tmp, data); err != nil {
		return errors.Join(err, removeFile(tmp))
	}
	if err := os.Rename(tmp, path); err != nil {
		return errors.Join(fmt.Errorf("keyring: rename %s: %w", tmp, err), removeFile(tmp))
	}
	return syncDir(filepath.Dir(path))
}
