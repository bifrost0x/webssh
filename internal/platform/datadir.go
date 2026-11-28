package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DataSubdirs are created below the data directory on every start, with the
// same owner-only access as the directory itself.
var DataSubdirs = []string{"logs", "keys"}

// probePrefix names the short-lived file of the write probe. It matches the
// readiness probe of the Python application, so a file left behind by a
// crash is recognised by both.
const probePrefix = ".webssh-ready-"

// ErrRelativeDataDir is returned for a data directory that is not absolute.
// Backup, restore and secret rotation treat the data directory as one fixed
// trust boundary, so a path that depends on the working directory is refused.
var ErrRelativeDataDir = errors.New("must be an absolute path")

var errNotDirectory = errors.New("exists and is not a directory")

// DataDirError explains why the data directory cannot be used and, where an
// operator can fix it, how.
type DataDirError struct {
	Path string
	Op   string
	Hint string
	Err  error
}

func (e *DataDirError) Error() string {
	msg := fmt.Sprintf("data directory %s: %s: %v", e.Path, e.Op, e.Err)
	if e.Hint != "" {
		msg += "; " + e.Hint
	}
	return msg
}

func (e *DataDirError) Unwrap() error { return e.Err }

// PrepareDataDir resolves path to its canonical form, creates it and
// DataSubdirs, restricts all of them to the running identity and proves that
// the directory is writable. It returns the canonical path, which callers use
// from then on.
//
// Restricting access runs on every start, so permissions that were widened by
// hand are narrowed again. Existing files are never changed.
func PrepareDataDir(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", &DataDirError{Path: path, Op: "check path", Err: ErrRelativeDataDir}
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", ownershipError(path, "create", err)
	}
	root, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", &DataDirError{Path: path, Op: "resolve", Err: err}
	}
	if err := restrictDir(root); err != nil {
		return "", ownershipError(root, "restrict access", err)
	}
	for _, name := range DataSubdirs {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", ownershipError(dir, "create", err)
		}
		// An existing entry must be a directory (a link to one is accepted,
		// as mkdir -p does); a file of that name is reported, not changed.
		if info, err := os.Stat(dir); err != nil {
			return "", &DataDirError{Path: dir, Op: "check", Err: err}
		} else if !info.IsDir() {
			return "", &DataDirError{Path: dir, Op: "check", Err: errNotDirectory}
		}
		if err := restrictDir(dir); err != nil {
			return "", ownershipError(dir, "restrict access", err)
		}
	}
	if err := ProbeDataDir(root); err != nil {
		return "", ownershipError(root, "write probe", err)
	}
	return root, nil
}

// CheckDataDir is the read-only counterpart of PrepareDataDir for commands
// that must leave the data directory as it is: path must be absolute and
// name an existing directory. Nothing is created, restricted or probed.
func CheckDataDir(path string) error {
	if !filepath.IsAbs(path) {
		return &DataDirError{Path: path, Op: "check path", Err: ErrRelativeDataDir}
	}
	info, err := os.Stat(path)
	if err != nil {
		return &DataDirError{Path: path, Op: "check", Err: err}
	}
	if !info.IsDir() {
		return &DataDirError{Path: path, Op: "check", Err: errNotDirectory}
	}
	return nil
}

// ProbeDataDir proves that dir is writable: it creates, writes, syncs and
// removes a file. Readiness checks use the same probe.
func ProbeDataDir(dir string) (err error) {
	f, err := os.CreateTemp(dir, probePrefix)
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() {
		err = errors.Join(err, os.Remove(name))
	}()
	if _, err := f.WriteString("ready"); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

func ownershipError(path, op string, err error) error {
	return &DataDirError{Path: path, Op: op, Err: err, Hint: ownershipHint()}
}
