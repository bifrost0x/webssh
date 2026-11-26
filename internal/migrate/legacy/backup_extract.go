package legacy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
)

// ExtractResult counts the members ExtractBackup did not write.
type ExtractResult struct {
	// GoMembers are files under data/go/: a Python backup taken after a
	// way back carries the Go directory along. They are never restored or
	// opened (migration specification, section 5.6 step 7).
	GoMembers int
	// LogMembers are files under data/logs/, which Python's restore
	// ignores as well.
	LogMembers int
}

// ExtractBackup writes the verified files of b below dest, which must be
// an existing, empty directory owned by the caller, except data/go/ and
// data/logs/. Every file is re-hashed while it is written, so a change of
// the archive after OpenBackup is detected. Files get mode 0600 and
// directories 0700; paths are normalised as Python normalises them. The
// result is a legacy DATA_DIR that Open reads with PrivateCopy.
func ExtractBackup(b *Backup, dest string, limits BackupLimits) (ExtractResult, error) {
	var res ExtractResult
	root, err := os.OpenRoot(dest)
	if err != nil {
		return res, fmt.Errorf("legacy: open extraction directory: %w", err)
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return res, fmt.Errorf("legacy: read extraction directory: %w", err)
	}
	if len(entries) != 0 {
		return res, errors.New("legacy: extraction directory is not empty")
	}
	for _, entry := range b.Manifest.Files {
		target, _ := normalizeBackupPath(entry.Path) // validated by parseBackupManifest
		top, _, _ := strings.Cut(target, "/")
		switch top {
		case "go":
			res.GoMembers++
			continue
		case "logs":
			res.LogMembers++
			continue
		}
		if dir := path.Dir(target); dir != "." {
			if err := root.MkdirAll(dir, 0o700); err != nil {
				return res, fmt.Errorf("legacy: create %q: %w", dir, err)
			}
		}
		if err := extractOne(root, b, entry, target, limits); err != nil {
			return res, err
		}
	}
	return res, nil
}

func extractOne(root *os.Root, b *Backup, entry BackupFile, target string, limits BackupLimits) error {
	out, err := root.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("legacy: create %q: %w", target, err)
	}
	copyErr := copyMember(out, b.files[backupDataPrefix+entry.Path], entry, limits)
	syncErr := out.Sync()
	closeErr := out.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("legacy: extract %q: %w", target, err)
	}
	return nil
}
