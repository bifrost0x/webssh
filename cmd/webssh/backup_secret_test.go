package main

import (
	"archive/tar"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/config"
)

// archiveMembers lists the member names of a tar archive.
func archiveMembers(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	names := map[string]bool{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names[h.Name] = true
	}
}

// With SECRET_KEY only in the environment, the Python release never had
// the key in DATA_DIR and so never in an export. backup create leaves it
// out by default, keeps the material, and the archive restores with the
// same environment. --include-secret-key adds the key on request.
func TestBackupCreateLeavesOutTheEnvironmentSecret(t *testing.T) {
	dir := adminEnv(t)
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatal(e)
	}
	if _, err := os.Lstat(filepath.Join(dir, "secret_key")); !os.IsNotExist(err) {
		t.Fatalf("the test expects SECRET_KEY from the environment only: %v", err)
	}
	plain := filepath.Join(t.TempDir(), "plain.tar")
	code, out, e := runIn(t, "", "webssh", "backup", "create", "--destination", plain, "--confirm-offline")
	if code != 0 || strings.Contains(out, "It contains SECRET_KEY") || !strings.Contains(out, "environment") {
		t.Fatalf("create: %d %q %q", code, out, e)
	}
	m := archiveMembers(t, plain)
	if m["data/secret_key"] || !m["data/go/keyring-material"] {
		t.Fatalf("members of the default export: %v", m)
	}
	with := filepath.Join(t.TempDir(), "with.tar")
	code, out, e = runIn(t, "", "webssh", "backup", "create", "--destination", with, "--include-secret-key", "--confirm-offline")
	if code != 0 || !strings.Contains(out, "It contains SECRET_KEY") || !archiveMembers(t, with)["data/secret_key"] {
		t.Fatalf("create --include-secret-key: %d %q %q", code, out, e)
	}
	if code, _, e := runIn(t, "", "webssh", "backup", "create", "--destination", filepath.Join(t.TempDir(), "x.tar"),
		"--include-secret-key", "--without-secret-key", "--confirm-offline"); code != 2 || !strings.Contains(e, "usage") {
		t.Fatalf("both flags: %d %q", code, e)
	}
	if code, _, e := runIn(t, "password2\npassword2\n", "webssh", "create-admin", "--username", "late"); code != 0 {
		t.Fatal(e)
	}
	if code, out, e := runIn(t, "", "webssh", "backup", "restore", plain, "--confirm-offline"); code != 0 || out != "Backup restored and verified.\n" {
		t.Fatalf("restore with the same environment: %d %q %q", code, out, e)
	}
	if names := storedUsernames(t); len(names) != 1 || names[0] != "admin1" {
		t.Fatalf("accounts after the restore: %v", names)
	}
}

// The purge backup follows the same rule: with SECRET_KEY only in the
// environment it holds the material but not the key, and it verifies
// with the key of the environment.
func TestPurgeBackupLeavesOutTheEnvironmentSecret(t *testing.T) {
	dir := extractGolden(t, "datadir-extended.tar")
	if err := os.Remove(filepath.Join(dir, "secret_key")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	env, lookup := k10Env(t, dir)
	for k, v := range env {
		t.Setenv(k, v)
	}
	log := slog.New(slog.DiscardHandler)
	cfg, err := bootstrapConfig(lookup, log)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecretSource != config.SecretFromEnvironment {
		t.Fatalf("secret source %q", cfg.SecretSource)
	}
	st, err := startMigration(t.Context(), cfg, lookup, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil || !st.Migrated {
		t.Fatalf("migration: %s %v", st.State, err)
	}
	target := t.TempDir()
	if code, out, e := runIn(t, "", "webssh", "legacy", "purge", "--backup-to", target, "--yes"); code != 0 {
		t.Fatalf("purge: %d %q %q", code, out, e)
	}
	archives, err := filepath.Glob(filepath.Join(target, "*.tar"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("purge backups %v %v", archives, err)
	}
	if m := archiveMembers(t, archives[0]); m["data/secret_key"] || !m["data/go/keyring-material"] {
		t.Fatalf("members of the purge backup: %v", m)
	}
	if _, err := backup.VerifyWith(t.Context(), archives[0], backup.VerifyOptions{Secret: []byte(env["SECRET_KEY"])}); err != nil {
		t.Fatalf("verify with the environment secret: %v", err)
	}
}
