package main

import (
	"bytes"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/store"
)

// backupEnv is the environment of a system whose data directory and
// backup directory survive a restart within the test.
func backupEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"DATA_DIR": filepath.Join(t.TempDir(), "data"), "SECRET_KEY": "backup-system-secret-0123456789abcdef",
		"SESSION_COOKIE_SECURE": "false", "BOOTSTRAP_REGISTRATION_ENABLED": "true", "TMPDIR": t.TempDir(),
		"ADMIN_PANEL_ENABLED": "true", "BACKUP_TEMP_DIR": t.TempDir(), "RATELIMIT_ENABLED": "false",
	}
}

func openEnv(t *testing.T, env map[string]string) (*system, *httptest.Server, func()) {
	t.Helper()
	sys, err := openSystem(t.Context(), bootInput{lookup: lookupMap(maps.Clone(env)), log: slog.New(slog.DiscardHandler),
		stopping: func() bool { return false }, fastHashing: true})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(sys.handler())
	closed := false
	stop := func() {
		if closed {
			return
		}
		closed = true
		ts.Close()
		if err := sys.close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}
	t.Cleanup(stop)
	return sys, ts, stop
}

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return out
}

// waitStatus polls an operation until it reaches want.
func waitStatus(t *testing.T, c *http.Client, base, id, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, body := get(t, c, base+"/admin/api/backups/"+id)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: %d %s", resp.StatusCode, body)
		}
		rec := decode(t, body)
		switch rec["status"] {
		case want:
			return rec
		case "failed":
			t.Fatalf("operation failed: %s", body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("operation %s did not reach %s", id, want)
	return nil
}

func rawPost(t *testing.T, c *http.Client, base, path string, body []byte, grant string) (int, []byte) {
	t.Helper()
	_, page := get(t, c, base+"/security")
	m := csrfMeta.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no CSRF meta tag")
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Origin", base)
	req.Header.Set("X-CSRFToken", m[1])
	req.Header.Set(accounts.StepUpHeader, grant)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func countRows(t *testing.T, db *store.DB, query string) int {
	t.Helper()
	var n int
	if err := db.Read(t.Context(), func(tx *store.Tx) error { return tx.QueryRowContext(t.Context(), query).Scan(&n) }); err != nil {
		t.Fatal(err)
	}
	return n
}

// The online backup and restore through the whole server (C-BAK-01 to
// -04, -06): the export leaves out SSH keys, downloads once, verifies on
// upload, restores after two confirmations through maintenance and a
// restart, and the restored installation shows the recovery notice.
func TestOnlineBackupAndRestoreThroughTheServer(t *testing.T) {
	env := backupEnv(t)
	sys, ts, stop := openEnv(t, env)
	const pw = "admin-password-1"
	admin := signUp(t, ts.URL, "admin1", pw)
	if _, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "carol", Password: "carol-password-1", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO vault_ssh_keys VALUES ('k1', 1, 0, 'key', 'ed25519', '', '', x'00', '', 'usable')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/backups", nil, adminGrant(t, admin, ts.URL, "backup.create", "new", pw))
	if status != http.StatusAccepted {
		t.Fatalf("create: %d %s", status, body)
	}
	id := decode(t, body)["operation_id"].(string)
	waitStatus(t, admin, ts.URL, id, "ready")
	if _, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "dave", Password: "dave-password-1", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}

	code, archive := rawPost(t, admin, ts.URL, "/admin/api/backups/"+id+"/download", nil, adminGrant(t, admin, ts.URL, "backup.download", id, pw))
	if code != http.StatusOK || len(archive) < 1024 {
		t.Fatalf("download: %d %d bytes", code, len(archive))
	}
	if code, _ := rawPost(t, admin, ts.URL, "/admin/api/backups/"+id+"/download", nil, adminGrant(t, admin, ts.URL, "backup.download", id, pw)); code != http.StatusNotFound {
		t.Fatalf("second download: %d", code)
	}
	// The export holds no SSH key and opens with the active SECRET_KEY.
	p := filepath.Join(t.TempDir(), "export.tar")
	if err := os.WriteFile(p, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	exported := filepath.Join(t.TempDir(), "export.db")
	v, err := backup.VerifyWith(t.Context(), p, backup.VerifyOptions{Secret: []byte(env["SECRET_KEY"]), Database: exported})
	if err != nil || v.Manifest.Reason != backup.ReasonExport || !v.Manifest.IncludesSecretKey {
		t.Fatalf("export: %+v, %v", v.Manifest, err)
	}
	edb, err := store.Open(t.Context(), exported, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, edb, `SELECT count(*) FROM vault_ssh_keys`); n != 0 {
		t.Fatalf("the export holds %d SSH keys", n)
	}
	_ = edb.Close()
	if bytes.Contains(archive, []byte("carol-password-1")) {
		t.Fatal("a password in clear in the archive")
	}

	code, out := rawPost(t, admin, ts.URL, "/admin/api/backups/upload", archive, adminGrant(t, admin, ts.URL, "backup.upload", "upload", pw))
	if code != http.StatusAccepted {
		t.Fatalf("upload: %d %s", code, out)
	}
	up := decode(t, string(out))["operation_id"].(string)
	rec := waitStatus(t, admin, ts.URL, up, "verified")
	if s := rec["summary"].(map[string]any); s["compatible"] != true || s["compatibility_reason"] != backup.ReasonCurrent {
		t.Fatalf("summary %v", s)
	}
	status, body = apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/backups/"+up+"/restore/prepare",
		map[string]any{"acknowledge_sensitive_restore": true}, adminGrant(t, admin, ts.URL, "backup.restore_prepare", up, pw))
	if status != http.StatusOK {
		t.Fatalf("prepare: %d %s", status, body)
	}
	token := decode(t, body)["confirmation_token"].(string)
	status, body = apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/backups/"+up+"/restore",
		map[string]any{"confirmation_token": token, "confirmation_phrase": "WRONG", "confirm_destructive_restore": true},
		adminGrant(t, admin, ts.URL, "backup.restore", up, pw))
	if status != http.StatusBadRequest {
		t.Fatalf("wrong phrase: %d %s", status, body)
	}
	status, body = apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/backups/"+up+"/restore",
		map[string]any{"confirmation_token": token, "confirmation_phrase": "RESTORE", "confirm_destructive_restore": true},
		adminGrant(t, admin, ts.URL, "backup.restore", up, pw))
	if status != http.StatusAccepted {
		t.Fatalf("restore: %d %s", status, body)
	}
	select {
	case <-sys.restart:
	case <-time.After(30 * time.Second):
		t.Fatal("no restart requested")
	}
	if resp, _ := get(t, admin, ts.URL+"/login"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not in maintenance: %d", resp.StatusCode)
	}
	if resp, _ := get(t, admin, ts.URL+"/ready"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("ready in maintenance: %d", resp.StatusCode)
	}
	stop()

	// The restart activates the restore.
	sys, ts, _ = openEnv(t, env)
	if _, err := sys.accounts.ByUsername(t.Context(), "carol"); err != nil {
		t.Fatalf("carol after the restore: %v", err)
	}
	if _, err := sys.accounts.ByUsername(t.Context(), "dave"); err == nil {
		t.Fatal("an account created after the backup survived the restore")
	}
	if n := countRows(t, sys.db, `SELECT count(*) FROM vault_ssh_keys`); n != 0 {
		t.Fatalf("%d SSH keys after restoring an export", n)
	}
	admin = signIn(t, ts.URL, "admin1", pw)
	resp, check := get(t, admin, ts.URL+"/api/account/recovery-check")
	rc := decode(t, check)
	if resp.StatusCode != http.StatusOK || rc["needs_review"] != true || rc["restored_at"] == nil {
		t.Fatalf("recovery check: %d %s", resp.StatusCode, check)
	}
	status, body = apiCall(t, admin, ts.URL, http.MethodPost, "/api/account/recovery-check", map[string]any{"restored_at": rc["restored_at"]}, "")
	if status != http.StatusOK || !strings.Contains(body, `"needs_review":false`) {
		t.Fatalf("review: %d %s", status, body)
	}
	resp, st := get(t, admin, ts.URL+"/admin/api/backups/restore/status")
	if resp.StatusCode != http.StatusOK || decode(t, st)["state"] != "succeeded" {
		t.Fatalf("restore status: %d %s", resp.StatusCode, st)
	}
}
