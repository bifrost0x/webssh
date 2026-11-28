package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/platform"
)

// effectiveUID is os.Geteuid; tests replace it to see a directory of
// their own as foreign.
var effectiveUID = os.Geteuid

// backupTempRoot is BACKUP_TEMP_DIR as an absolute path, by default
// webssh-backup-operations in the system's temporary directory.
func backupTempRoot(cfg config.Config) (string, error) {
	root := cfg.BackupTempDir
	if root == "" {
		root = filepath.Join(os.TempDir(), "webssh-backup-operations")
	}
	return filepath.Abs(root)
}

// warnForeignBackupTempDir logs a warning when BACKUP_TEMP_DIR belongs to
// another user than the one the service runs as. That can only happen
// when the service runs as root (otherwise the chmod of backupNamespace
// fails): the owner can then open the directory again and read online
// backups, which hold SECRET_KEY and the keyring material. The start goes
// on, because a bind mount of another owner is a common root setup and
// refusing it would stop working installations at the update.
func warnForeignBackupTempDir(cfg config.Config, log *slog.Logger) {
	root, err := backupTempRoot(cfg)
	if err != nil {
		return
	}
	info, err := os.Lstat(root)
	if err != nil {
		return
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) == int64(effectiveUID()) {
		return
	}
	log.Warn("BACKUP_TEMP_DIR belongs to another user, who can read online backups including SECRET_KEY; "+
		"chown it to the service user or set BACKUP_TEMP_DIR to a directory of the service",
		"path", root, "owner_uid", st.Uid, "runtime_user", platform.RuntimeIdentity())
}
