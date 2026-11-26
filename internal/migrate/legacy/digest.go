package legacy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"
)

// FileStat is one regular file of the legacy source as the migration
// record stores it (migration specification, section 5.3).
type FileStat struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	MtimeNS int64  `json:"mtime_ns"`
	Inode   uint64 `json:"inode"`
	SHA256  string `json:"sha256"`
}

// Listing is the legacy source in byte order of the relative POSIX path.
type Listing struct {
	// ScannedAt is the time the scan started, in Unix nanoseconds; the
	// next scan needs it for the racy-clean rule.
	ScannedAt int64
	Files     []FileStat
	// Unsafe lists symbolic links and special files. During a migration
	// they are STOP; after activation they count as a change.
	Unsafe []string
}

// Digest is "sha256:" and the hex SHA-256 over one line
// "path NUL size NUL sha256(content) LF" per file. Directories, modes and
// timestamps are not part of it. An unsafe entry makes the digest differ
// from every digest a migration can record.
func (l Listing) Digest() string {
	h := sha256.New()
	for _, f := range l.Files {
		fmt.Fprintf(h, "%s\x00%d\x00%s\n", f.Path, f.Size, f.SHA256)
	}
	for _, u := range l.Unsafe {
		fmt.Fprintf(h, "%s\x00unsafe\n", u)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// bytesBelow sums the sizes of the files below prefix ("users").
func (l Listing) bytesBelow(prefix string) int64 {
	var n int64
	for _, f := range l.Files {
		if strings.HasPrefix(f.Path, prefix+"/") {
			n += f.Size
		}
	}
	return n
}

func (l Listing) size(path string) int64 {
	for _, f := range l.Files {
		if f.Path == path {
			return f.Size
		}
	}
	return 0
}

// racyWindow is the margin of the racy-clean rule: a file modified less
// than this before the previous scan may have changed again within the
// same timestamp tick, so its stat values prove nothing. File systems
// update mtime with a coarse clock (kernel ticks, NFS and SMB seconds).
const racyWindow = 2 * time.Second

// scanSource lists every regular file of the legacy source in dataDir:
// everything below DATA_DIR except the runtime paths, logs/ and go/. The
// walk never follows links. Files are opened read-only and only read.
//
// previous is the listing of an earlier scan that started at scannedAt
// (Unix nanoseconds). A file whose size, modification time and inode equal
// its entry there keeps that entry's hash, unless it is app.db, which
// SQLite rewrites in place with the same size, or its modification time is
// within racyWindow before scannedAt (the racy-clean rule of git). Every
// other file is hashed.
func scanSource(dataDir string, previous []FileStat, scannedAt int64) (Listing, error) {
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return Listing{}, fmt.Errorf("legacy: open data directory: %w", err)
	}
	defer root.Close()
	known := make(map[string]FileStat, len(previous))
	for _, f := range previous {
		known[f.Path] = f
	}
	l := Listing{ScannedAt: time.Now().UnixNano()}
	racyFrom := scannedAt - racyWindow.Nanoseconds()
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
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
		switch t := d.Type(); {
		case t.IsDir():
			return nil
		case !t.IsRegular():
			l.Unsafe = append(l.Unsafe, name)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("legacy: inspect %q: %w", name, err)
		}
		f := FileStat{Path: name, Size: info.Size(), MtimeNS: info.ModTime().UnixNano(), Inode: fileIdentity(info)}
		if old, ok := known[name]; ok && name != "app.db" && old.MtimeNS < racyFrom &&
			old.Size == f.Size && old.MtimeNS == f.MtimeNS && old.Inode == f.Inode {
			f.SHA256 = old.SHA256
		} else if f.SHA256, err = hashFile(root, name, info); err != nil {
			return err
		}
		l.Files = append(l.Files, f)
		return nil
	})
	if err != nil {
		return Listing{}, err
	}
	slices.SortFunc(l.Files, func(a, b FileStat) int { return strings.Compare(a.Path, b.Path) })
	slices.Sort(l.Unsafe)
	return l, nil
}

// hashFile hashes a file the walk saw as regular. It opens without
// blocking, so that a FIFO swapped in after the walk cannot stall the
// start, and checks on the open handle that it is still the same regular
// file.
func hashFile(root *os.Root, name string, info fs.FileInfo) (string, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return "", fmt.Errorf("legacy: open %q: %w", name, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return "", fmt.Errorf("%w: %q changed while it was read", ErrUnsafePath, name)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("legacy: read %q: %w", name, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// strictListing fails with ErrUnsafePath for a listing with links or
// special files (STOP during a migration, section 5.3).
func strictListing(l Listing) error {
	if len(l.Unsafe) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrUnsafePath, l.Unsafe[0])
}
