package legacy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
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
	// RuntimeMembers are files under data/tmp/, data/.access-revocations/
	// and data/.ldap-revocation-fences/, which Python's restore drops.
	RuntimeMembers int
	// CredentialMembers are remote credentials an export restore drops:
	// keys/, deleted_users/, credentials.json* and automation-vault.json*
	// (app/backup_manager.py _excluded_remote_credential_path).
	CredentialMembers int
}

// ExtractBackup writes the files of b that Python's restore in mode would
// restore below dest, which must be an existing, empty directory owned by
// the caller. data/go/ is never written. Every file is re-hashed while it
// is written, so a change of the archive after OpenBackup is detected.
// Files get mode 0600 and directories 0700; paths are normalised as Python
// normalises them. The result is a legacy DATA_DIR that Open reads with
// PrivateCopy and Restored(mode, ...).
func ExtractBackup(b *Backup, dest string, limits BackupLimits, mode RestoreMode) (ExtractResult, error) {
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
		if counter := restoreSkip(&res, target, mode); counter != nil {
			*counter++
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

// restoreSkip returns the counter of res for a member Python's restore
// drops, or nil for a member it restores. The top-level directory is compared after
// case folding and without trailing dots and spaces, as Python does,
// because Windows and macOS file systems map "LOGS." onto "logs"; the same
// applies to go/, so data/GO/ never reaches a Go data directory.
func restoreSkip(res *ExtractResult, target string, mode RestoreMode) *int {
	top, _, _ := strings.Cut(target, "/")
	switch strings.TrimRight(foldName(top), " .") {
	case "go":
		return &res.GoMembers
	case "logs":
		return &res.LogMembers
	case "tmp", ".access-revocations", ".ldap-revocation-fences":
		return &res.RuntimeMembers
	}
	if mode == RestoreExport && remoteCredentialPath(target) {
		return &res.CredentialMembers
	}
	return nil
}

// remoteCredentialPath is app/backup_manager.py
// _excluded_remote_credential_path: exports never restore reusable remote
// authentication material. Python compares these names exactly.
func remoteCredentialPath(p string) bool {
	parts := strings.Split(p, "/")
	if slices.Contains(parts, "keys") || parts[0] == "deleted_users" {
		return true
	}
	name := strings.TrimLeft(parts[len(parts)-1], ".")
	for _, base := range []string{"credentials.json", "automation-vault.json"} {
		if name == base || strings.HasPrefix(name, base+".") {
			return true
		}
	}
	return false
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
