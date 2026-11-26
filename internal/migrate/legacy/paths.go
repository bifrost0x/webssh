package legacy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
)

// maxFileBytes bounds every legacy file read into memory. Stores have
// their own, lower limits (stores.go).
const maxFileBytes = 64 << 20

// ErrUnsafePath reports a symbolic link or a special file in the legacy
// source. The migration specification treats it as STOP (section 5.3):
// Python rejects such entries, and following them could read another
// user's data or a file outside DATA_DIR.
var ErrUnsafePath = errors.New("legacy: symbolic link or special file in the legacy source")

// runtimePaths are the top-level entries of DATA_DIR that are not part of
// the legacy source (migration specification, section 2) or belong to Go.
var runtimePaths = []string{"logs", "tmp", ".access-revocations", ".ldap-revocation-fences", "go"}

func isRuntimePath(top string) bool {
	return slices.Contains(runtimePaths, top) || strings.HasPrefix(top, ".webssh-ready-")
}

// CheckTree walks the legacy source and fails with ErrUnsafePath on the
// first symbolic link, socket, FIFO or device. Runtime paths are skipped.
// The walk never follows links.
func (s *Source) CheckTree() error {
	return fs.WalkDir(s.root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("legacy: inspect %q: %w", name, err)
		}
		if name == "." {
			return nil
		}
		top, _, _ := strings.Cut(name, "/")
		if isRuntimePath(top) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if t := d.Type(); t&fs.ModeSymlink != 0 || !(t.IsRegular() || t.IsDir()) {
			return fmt.Errorf("%w: %q", ErrUnsafePath, name)
		}
		return nil
	})
}

// lstatChain checks every component of name without following links: all
// but the last must be directories, none may be a symbolic link. It
// returns the information of the last component.
func lstatChain(root *os.Root, name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) || name == "." {
		return nil, fmt.Errorf("legacy: invalid path %q", name)
	}
	parts := strings.Split(name, "/")
	var info fs.FileInfo
	for i := range parts {
		prefix := path.Join(parts[:i+1]...)
		var err error
		info, err = root.Lstat(prefix)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %q", ErrNotFound, name)
		}
		if err != nil {
			return nil, fmt.Errorf("legacy: inspect %q: %w", prefix, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %q", ErrUnsafePath, prefix)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, fmt.Errorf("%w: %q", ErrNotFound, name)
		}
	}
	return info, nil
}

// readLimited reads a regular file below root after lstatChain, and checks
// that the opened file is the one inspected.
func readLimited(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := lstatChain(root, name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrUnsafePath, name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("legacy: open %q: %w", name, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("legacy: stat %q: %w", name, err)
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%w: %q changed while it was opened", ErrUnsafePath, name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("legacy: read %q: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("legacy: %q exceeds %d bytes", name, limit)
	}
	return data, nil
}

// listDir lists a directory below the root. A missing directory yields
// nil; a symbolic link anywhere on the way, or an entry that is a link or
// a special file, is ErrUnsafePath.
func (s *Source) listDir(name string) ([]fs.DirEntry, error) {
	info, err := lstatChain(s.root, name)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("legacy: %q is not a directory", name)
	}
	entries, err := fs.ReadDir(s.root.FS(), name)
	if err != nil {
		return nil, fmt.Errorf("legacy: list %q: %w", name, err)
	}
	for _, e := range entries {
		if t := e.Type(); t&fs.ModeSymlink != 0 || !(t.IsRegular() || t.IsDir()) {
			return nil, fmt.Errorf("%w: %q", ErrUnsafePath, name+"/"+e.Name())
		}
	}
	return entries, nil
}

// SingleUserPath is a store of the single-user layout of very old
// releases (migration specification E35). Python 3.3.x does not read
// these as user data; the migration leaves them in place and reports
// them.
type SingleUserPath struct {
	Path  string
	Files int
	Bytes int64
}

// SingleUserPaths reports which of DATA_DIR/profiles.json, keys/ and
// commands/ exist, with the number and total size of their files.
func (s *Source) SingleUserPaths() ([]SingleUserPath, error) {
	var out []SingleUserPath
	for _, name := range []string{"profiles.json", "keys", "commands"} {
		info, err := lstatChain(s.root, name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		entry := SingleUserPath{Path: name}
		if !info.IsDir() {
			entry.Files, entry.Bytes = 1, info.Size()
			out = append(out, entry)
			continue
		}
		err = fs.WalkDir(s.root.FS(), name, func(_ string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			entry.Files++
			entry.Bytes += fi.Size()
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("legacy: inspect %q: %w", name, err)
		}
		out = append(out, entry)
	}
	return out, nil
}
