package legacy

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"slices"
	"strings"
)

// BackupLimits bound what an archive may expand to. The defaults are the
// Python defaults (config.py BACKUP_MAX_*).
type BackupLimits struct {
	Members       int
	FileSize      uint64
	TotalSize     uint64
	Compression   uint64 // maximum uncompressed/compressed ratio
	ManifestBytes uint64
}

// DefaultBackupLimits are the limits of the Python release.
var DefaultBackupLimits = BackupLimits{
	Members: 10000, FileSize: 1 << 30, TotalSize: 10 << 30, Compression: 200, ManifestBytes: 10 << 20,
}

// Backup is an opened, fully verified archive.
type Backup struct {
	Manifest BackupManifest
	files    map[string]*zip.File
	closer   io.Closer
}

// OpenBackup opens a Python backup archive file and verifies it; see
// OpenBackupReader.
func OpenBackup(path string, limits BackupLimits) (*Backup, error) {
	f, err := os.Open(path) // #nosec G304 -- the caller names the archive to restore
	if err != nil {
		return nil, backupError("archive is unreadable")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(backupError("archive is not a regular file"), f.Close())
	}
	b, err := OpenBackupReader(f, info.Size(), limits)
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	b.closer = f
	return b, nil
}

// OpenBackupReader verifies an archive completely: member names and
// types, limits, manifest, and the size and SHA-256 of every file. The
// database itself is checked after extraction (ExtractBackup, then Open
// with PrivateCopy and CheckBackupDatabase). r must stay readable until
// the Backup is no longer used.
func OpenBackupReader(r io.ReaderAt, size int64, limits BackupLimits) (*Backup, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, backupError("archive is unreadable")
	}
	b := &Backup{files: map[string]*zip.File{}}
	if err := b.verify(zr, limits); err != nil {
		return nil, err
	}
	return b, nil
}

// Close releases the archive file, if OpenBackup opened it.
func (b *Backup) Close() error {
	if b.closer == nil {
		return nil
	}
	return b.closer.Close()
}

// zipSymlink reports a member whose Unix mode bits mark a symbolic link,
// read from the external attributes for every creator as Python does.
func zipSymlink(f *zip.File) bool {
	mode := f.ExternalAttrs >> 16
	return mode != 0 && mode&0o170000 == 0o120000
}

// ratioExceeded is uncompressed / max(compressed, 1) > limit without
// rounding or overflow.
func ratioExceeded(uncompressed, compressed, limit uint64) bool {
	compressed = max(compressed, 1)
	if compressed > math.MaxUint64/max(limit, 1) {
		return false
	}
	return uncompressed > compressed*limit
}

func (b *Backup) verify(zr *zip.Reader, limits BackupLimits) error {
	if len(zr.File) > limits.Members {
		return backupError("too many members")
	}
	var total uint64
	for _, f := range zr.File {
		name := strings.TrimSuffix(f.Name, "/")
		if _, dup := b.files[f.Name]; dup {
			return backupError("duplicate member")
		}
		if name != "" && !safeBackupPath(name) {
			return backupError("unsafe member path %q", f.Name)
		}
		if zipSymlink(f) {
			return backupError("symbolic link member %q", f.Name)
		}
		if f.Flags&0x1 != 0 {
			return backupError("encrypted member")
		}
		b.files[f.Name] = f
		if f.FileInfo().IsDir() || f.Name == backupManifestName {
			continue
		}
		total += f.UncompressedSize64
		if f.UncompressedSize64 > limits.FileSize || total > limits.TotalSize {
			return backupError("member exceeds size limits")
		}
		if f.UncompressedSize64 > 0 && ratioExceeded(f.UncompressedSize64, f.CompressedSize64, limits.Compression) {
			return backupError("member exceeds compression ratio limit")
		}
	}
	manifestFile, ok := b.files[backupManifestName]
	if !ok || manifestFile.UncompressedSize64 > limits.ManifestBytes {
		return backupError("archive must contain one manifest within limits")
	}
	payload, err := readMember(manifestFile, limits.ManifestBytes)
	if err != nil {
		return err
	}
	if b.Manifest, err = parseBackupManifest(payload); err != nil {
		return err
	}
	return b.verifyFiles(limits)
}

func (b *Backup) verifyFiles(limits BackupLimits) error {
	expected := map[string]bool{backupManifestName: true}
	hasDB := false
	for _, f := range b.Manifest.Files {
		norm, _ := normalizeBackupPath(f.Path) // validated by parseBackupManifest
		folded := strings.TrimRight(foldName(norm), " .")
		if slices.Contains(sqliteSidecars, folded) {
			return backupError("archive contains SQLite runtime sidecars")
		}
		if folded == backupDatabase && f.Path != backupDatabase {
			return backupError("archive contains an ambiguous database path")
		}
		hasDB = hasDB || f.Path == backupDatabase
		expected[backupDataPrefix+f.Path] = true
	}
	for name, f := range b.files {
		if !f.FileInfo().IsDir() && !expected[name] {
			return backupError("members do not match the manifest")
		}
	}
	if !hasDB {
		return backupError("database is missing")
	}
	for _, entry := range b.Manifest.Files {
		f, ok := b.files[backupDataPrefix+entry.Path]
		if !ok || f.FileInfo().IsDir() || f.UncompressedSize64 != entry.Size {
			return backupError("size mismatch for %q", entry.Path)
		}
		if err := checkMember(f, entry, limits); err != nil {
			return err
		}
	}
	return nil
}

// checkMember streams a member and compares size and SHA-256.
func checkMember(f *zip.File, entry BackupFile, limits BackupLimits) error {
	return copyMember(io.Discard, f, entry, limits)
}

func copyMember(dst io.Writer, f *zip.File, entry BackupFile, limits BackupLimits) error {
	limit := min(entry.Size, limits.FileSize)
	if limit >= math.MaxInt64 {
		return backupError("member exceeds size limits")
	}
	rc, err := f.Open()
	if err != nil {
		return backupError("cannot read %q", entry.Path)
	}
	defer rc.Close()
	h := sha256.New()
	counter := &countingWriter{}
	// Read one byte more than allowed so that an overlong member is seen.
	if _, err := io.Copy(io.MultiWriter(dst, h, counter), io.LimitReader(rc, int64(limit)+1)); err != nil { // #nosec G115 -- limit < MaxInt64, checked above
		return backupError("cannot read %q", entry.Path)
	}
	if counter.n != entry.Size || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
		return backupError("checksum mismatch for %q", entry.Path)
	}
	return nil
}

type countingWriter struct{ n uint64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += uint64(len(p))
	return len(p), nil
}

func readMember(f *zip.File, limit uint64) ([]byte, error) {
	if limit >= math.MaxInt64 {
		return nil, backupError("manifest limit too large")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, backupError("cannot read %q", f.Name)
	}
	defer rc.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(rc, int64(limit)+1)); err != nil || uint64(buf.Len()) > limit { // #nosec G115 -- limit < MaxInt64, checked above; Len is never negative
		return nil, backupError("cannot read %q", f.Name)
	}
	return buf.Bytes(), nil
}
