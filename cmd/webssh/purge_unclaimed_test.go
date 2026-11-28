package main

import (
	"archive/tar"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Files in DATA_DIR that no migration step reads and no step reports as
// kept in place are named before the purge removes them and go into the
// purge backup.
func TestPurgeKeepsUnclaimedFilesInTheBackup(t *testing.T) {
	dir := extractGolden(t, "../datadir.tar")
	extra := map[string]string{
		"certs/ldap-ca.pem":              "-----BEGIN CERTIFICATE-----\noperator file\n-----END CERTIFICATE-----\n",
		"users/user_3/notes-export.md":   "a file the user directory holds that no step reads\n",
		"users/user_3/profiles.json.bak": "[]\n",
	}
	for rel, body := range extra {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
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
	st, err := startMigration(t.Context(), cfg, lookup, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil || !st.Migrated {
		t.Fatalf("migration: %s %v", st.State, err)
	}
	target := t.TempDir()
	code, out, e := runIn(t, "", "webssh", "legacy", "purge", "--backup-to", target, "--yes")
	if code != 0 {
		t.Fatalf("purge: %d\n%s%s", code, out, e)
	}
	members := map[string]bool{}
	archives, _ := filepath.Glob(filepath.Join(target, "webssh-backup-*.tar"))
	if len(archives) != 1 {
		t.Fatalf("archives: %v", archives)
	}
	f, err := os.Open(archives[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		members[h.Name] = true
	}
	for rel := range extra {
		_, statErr := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
		removed := errors.Is(statErr, fs.ErrNotExist)
		inBackup := members["data/"+rel]
		if removed && !inBackup {
			t.Errorf("%s was removed by the purge and is not in the purge backup", rel)
		}
		if !strings.Contains(out, "  "+rel+"\n") {
			t.Errorf("the confirmation does not name %s", rel)
		}
	}
	if !strings.Contains(out, "Legacy data removed") {
		t.Fatalf("unexpected output %q", out)
	}
}
