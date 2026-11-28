package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

// A BACKUP_TEMP_DIR that belongs to another user stays usable for that
// user even after the chmod: the start warns and names the owner, and
// goes on (sec-low #76). The namespace below it is checked as before.
func TestForeignBackupTempDirOnlyWarns(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "recovery")
	cfg := config.Config{DataDir: filepath.Join(base, "data"), BackupTempDir: root}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	if _, err := backupNamespace(cfg); err != nil {
		t.Fatal(err)
	}
	warnForeignBackupTempDir(cfg, log)
	if logs.Len() != 0 {
		t.Fatalf("own BACKUP_TEMP_DIR warned: %s", logs.String())
	}

	own := effectiveUID
	t.Cleanup(func() { effectiveUID = own })
	effectiveUID = func() int { return own() + 1 }
	if _, err := backupNamespace(cfg); err != nil {
		t.Fatalf("a foreign owner stopped the start: %v", err)
	}
	warnForeignBackupTempDir(cfg, log)
	out := logs.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "BACKUP_TEMP_DIR") ||
		!strings.Contains(out, fmt.Sprintf("owner_uid=%d", os.Getuid())) {
		t.Fatalf("warning for a foreign BACKUP_TEMP_DIR: %q", out)
	}

	logs.Reset()
	warnForeignBackupTempDir(config.Config{DataDir: cfg.DataDir, BackupTempDir: filepath.Join(base, "missing")}, log)
	if logs.Len() != 0 {
		t.Fatalf("a missing BACKUP_TEMP_DIR warned: %s", logs.String())
	}
}
