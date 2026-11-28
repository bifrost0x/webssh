package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/config"
)

// Unraid creates the recovery folder as nobody:users with mode 0777. Like
// ensure_backup_temp_dir of the Python release, the start makes the
// staging root private, and a link in its place is refused (RC0-5).
func TestBackupNamespaceMakesTheRootPrivate(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "recovery")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: filepath.Join(base, "data"), BackupTempDir: root}
	if _, err := backupNamespace(cfg); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o700 {
		t.Fatalf("BACKUP_TEMP_DIR mode %o, want 700", mode)
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := backupNamespace(config.Config{DataDir: cfg.DataDir, BackupTempDir: link}); err == nil {
		t.Fatal("a link as BACKUP_TEMP_DIR was accepted")
	}
}
