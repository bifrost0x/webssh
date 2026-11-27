package main

import (
	json "encoding/json/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

const goldenBackups = "../../tests/golden/fixture/artifacts/backups"

func fixtureSecret(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../tests/golden/fixture/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		SecretKey struct {
			Value string `json:"value"`
		} `json:"secret_key"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m.SecretKey.Value
}

func storedUsernames(t *testing.T) []string {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	g, err := openGoData(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	var names []string
	err = g.db.Read(t.Context(), func(tx *store.Tx) error {
		rows, err := tx.QueryContext(t.Context(), `SELECT username FROM accounts_users ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			names = append(names, n)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// backup create, verify and restore offline (C-BAK-07), in both the
// webssh and the deprecated Python command form.
func TestBackupCommandsRoundTrip(t *testing.T) {
	dir := adminEnv(t)
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatal(e)
	}
	archive := filepath.Join(t.TempDir(), "b.tar")
	if code, _, e := runIn(t, "", "webssh", "backup", "create", "--destination", archive); code != 1 || !strings.Contains(e, "--confirm-offline") {
		t.Fatalf("without --confirm-offline: %d %q", code, e)
	}
	if code, _, e := runIn(t, "", "webssh", "backup", "create", "--destination", filepath.Join(dir, "x.tar"), "--confirm-offline"); code != 1 || !strings.Contains(e, "outside DATA_DIR") {
		t.Fatalf("inside DATA_DIR: %d %q", code, e)
	}
	code, out, e := runIn(t, "", "webssh", "backup", "create", "--destination", archive, "--confirm-offline")
	if code != 0 || !strings.HasPrefix(out, "Backup created and verified: "+archive+" (") {
		t.Fatalf("create: %d %q %q", code, out, e)
	}
	if info, err := os.Stat(archive); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode %v %v", info, err)
	}
	code, out, e = runIn(t, "", "/app/entrypoint.sh", "flask", "--app", "start:app", "backup", "verify", archive)
	if code != 0 || out != "Backup verified (3 files, format v1, data schema 1, restore compatible).\n" || !strings.Contains(e, "deprecated") {
		t.Fatalf("verify: %d %q %q", code, out, e)
	}
	without := filepath.Join(t.TempDir(), "w.tar")
	if code, _, e := runIn(t, "", "webssh", "backup", "create", "--destination", without, "--without-secret-key", "--confirm-offline"); code != 0 {
		t.Fatal(e)
	}
	if code, _, e := runIn(t, "password2\npassword2\n", "webssh", "create-admin", "--username", "late"); code != 0 {
		t.Fatal(e)
	}
	code, out, e = runIn(t, "", "webssh", "backup", "restore", archive, "--confirm-offline")
	if code != 0 || out != "Backup restored and verified.\n" {
		t.Fatalf("restore: %d %q %q", code, out, e)
	}
	if names := storedUsernames(t); len(names) != 1 || names[0] != "admin1" {
		t.Fatalf("accounts after the restore: %v", names)
	}
	// The archive without SECRET_KEY restores on the same installation.
	if code, _, e := runIn(t, "", "webssh", "backup", "restore", without, "--confirm-offline"); code != 0 {
		t.Fatalf("restore without secret: %q", e)
	}
	// A foreign SECRET_KEY is refused and nothing changes.
	t.Setenv("SECRET_KEY", "another-secret-0123456789abcdef0123456789")
	if code, _, e := runIn(t, "", "webssh", "backup", "restore", archive, "--confirm-offline"); code != 1 || !strings.Contains(e, "another SECRET_KEY") {
		t.Fatalf("foreign secret: %d %q", code, e)
	}
	t.Setenv("SECRET_KEY", testSecret)
	if names := storedUsernames(t); len(names) != 1 {
		t.Fatalf("a refused restore changed the accounts: %v", names)
	}
}

// A Python recovery snapshot of the golden data set restores on a new
// installation through the migration; the server then starts in S2 with
// every account.
func TestBackupRestorePythonArchiveOnNewInstallation(t *testing.T) {
	adminEnv(t)
	t.Setenv("SECRET_KEY", fixtureSecret(t))
	archive := filepath.Join(goldenBackups, "online-recovery-snapshot.zip")
	code, out, e := runIn(t, "", "webssh", "backup", "verify", archive)
	if code != 0 || !strings.Contains(out, "format v2, data schema 2, restore compatible)") {
		t.Fatalf("verify: %d %q %q", code, out, e)
	}
	code, out, e = runIn(t, "", "webssh", "backup", "restore", archive, "--confirm-offline", "--recovery-snapshot")
	if code != 0 {
		t.Fatalf("restore: %d %q %q", code, out, e)
	}
	names := storedUsernames(t)
	if len(names) < 10 || !strings.Contains(strings.Join(names, ","), "local_user") {
		t.Fatalf("accounts: %v", names)
	}
}

// Crash injection through the server: a restore staged and committed
// (the process died before the restart) is activated by the next start.
func TestServerStartActivatesACommittedRestore(t *testing.T) {
	env := backupEnv(t)
	sys, _, stop := openEnv(t, env)
	cfg := sys.cfg
	archive := filepath.Join(t.TempDir(), "a.tar")
	_, material, err := keyring.MaterialLocation(cfg.DataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := backupNamespace(cfg)
	work, _ := os.MkdirTemp(ns, "t-")
	if _, err := backup.Export(t.Context(), backup.ExportRequest{Source: sys.db, Path: archive, Work: work, SecretKey: cfg.SecretKey.Bytes(),
		Material: material, KeyID: sys.ring.KeyID(), Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	in, err := backupInstallation(cfg, sys.lookup, sys.db, ns)
	if err != nil {
		t.Fatal(err)
	}
	goDir := filepath.Join(cfg.DataDir, keyring.GoDirName)
	if err := backup.Begin(goDir, "crash", time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := backup.Stage(t.Context(), in, backup.StageRequest{OperationID: "crash", Archive: archive, Portable: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.Commit(goDir, st, in, time.Now()); err != nil {
		t.Fatal(err)
	}
	stop()
	_, ts, _ := openEnv(t, env)
	if resp, _ := get(t, &http.Client{}, ts.URL+"/ready"); resp.StatusCode != http.StatusOK {
		t.Fatalf("ready after activation: %d", resp.StatusCode)
	}
	if state, _ := backup.Status(goDir, time.Hour, time.Now()); state != string(backup.RestoreSucceeded) {
		t.Fatalf("state %s", state)
	}
}

// A restore whose rollback failed keeps the server in maintenance over a
// restart; `webssh backup restore` resolves it.
func TestFailedRollbackKeepsMaintenanceUntilACLIRestore(t *testing.T) {
	env := backupEnv(t)
	sys, _, stop := openEnv(t, env)
	cfg := sys.cfg
	archive := filepath.Join(t.TempDir(), "a.tar")
	_, material, _ := keyring.MaterialLocation(cfg.DataDir, false)
	ns, _ := backupNamespace(cfg)
	work, _ := os.MkdirTemp(ns, "t-")
	if _, err := backup.Export(t.Context(), backup.ExportRequest{Source: sys.db, Path: archive, Work: work, SecretKey: cfg.SecretKey.Bytes(),
		Material: material, KeyID: sys.ring.KeyID(), Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	stop()
	goDir := filepath.Join(cfg.DataDir, keyring.GoDirName)
	failed := `{"format":1,"operation_id":"op","state":"rollback_failed","started_at":"2026-11-27T00:00:00Z",` +
		`"updated_at":"2026-11-27T00:00:00Z","message":"Restore failed and the rollback failed"}`
	if err := os.WriteFile(filepath.Join(goDir, backup.JournalName), []byte(failed), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_, ts, stop := openEnv(t, env)
		c := &http.Client{}
		if resp, _ := get(t, c, ts.URL+"/ready"); resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("ready during maintenance: %d", resp.StatusCode)
		}
		if resp, _ := get(t, c, ts.URL+"/login"); resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("login during maintenance: %d", resp.StatusCode)
		}
		stop()
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	if code, _, e := runIn(t, "", "webssh", "backup", "restore", archive, "--confirm-offline"); code != 0 {
		t.Fatalf("CLI restore: %q", e)
	}
	_, ts, _ := openEnv(t, env)
	if resp, _ := get(t, &http.Client{}, ts.URL+"/ready"); resp.StatusCode != http.StatusOK {
		t.Fatalf("ready after the CLI restore: %d", resp.StatusCode)
	}
}
