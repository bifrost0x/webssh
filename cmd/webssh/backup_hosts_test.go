package main

import (
	json "encoding/json/v2"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/store"
)

// A backup made on host A restores on host B, whose own SECRET_KEY is
// another one in DATA_DIR/secret_key, as with the Python release: the
// archive's SECRET_KEY replaces B's, and every secret of the extended
// golden data set (SSH keys, saved passwords, TOTP, GitHub client secret)
// opens to the same plaintext afterwards. With SECRET_KEY set in the
// environment of B the restore is refused before anything changes, since
// the environment would stay active and leave the secrets unreadable.
func TestBackupFromAnotherHostBringsItsSecret(t *testing.T) {
	hostA := migratedPurged(t)
	before := secrets(t)
	secretA := readSecret(t, hostA)
	// The CLI backup is a portable export (no SSH keys or saved
	// passwords, as in Python); the archive of `migrate --replace` keeps
	// every secret.
	export := filepath.Join(t.TempDir(), "host-a-export.tar")
	if out := runCLI(t, "backup", "create", "--destination", export, "--confirm-offline"); out.Code != 0 {
		t.Fatalf("backup on host A: %+v", out)
	}
	archive := fullArchive(t, hostA, secretA)

	hostB := filepath.Join(t.TempDir(), "host-b")
	rotationEnv(t, hostB)
	if code, _, e := runIn(t, "password-b1\npassword-b1\n", "webssh", "create-admin", "--username", "admin_b"); code != 0 {
		t.Fatal(e)
	}
	secretB := readSecret(t, hostB)
	if secretB == secretA {
		t.Fatal("host B was set up with the secret of host A")
	}

	t.Setenv("SECRET_KEY", secretB)
	out := runCLI(t, "backup", "restore", archive, "--confirm-offline")
	if out.Code != 1 || !strings.Contains(out.Stderr, "another SECRET_KEY") || !strings.Contains(out.Stderr, "environment") {
		t.Fatalf("restore with SECRET_KEY from the environment: %+v", out)
	}
	if names := storedUsernames(t); len(names) != 1 || names[0] != "admin_b" || readSecret(t, hostB) != secretB {
		t.Fatalf("a refused restore changed host B: %v", names)
	}

	rotationEnv(t, hostB)
	if out := runCLI(t, "backup", "restore", archive, "--confirm-offline"); out.Code != 0 {
		t.Fatalf("restore on host B: %+v", out)
	}
	if got := readSecret(t, hostB); got != secretA {
		t.Fatal("host B does not use the SECRET_KEY of the archive")
	}
	if after := secrets(t); !maps.Equal(after, before) {
		t.Fatalf("the secrets of host A do not open on host B (%d of %d)", len(after), len(before))
	}
	// The export restores too; it brings the account secrets only.
	if out := runCLI(t, "backup", "restore", export, "--confirm-offline"); out.Code != 0 {
		t.Fatalf("restore of the export on host B: %+v", out)
	}
	portable := maps.Clone(before)
	maps.DeleteFunc(portable, func(k, _ string) bool {
		return strings.HasPrefix(k, "key ") || strings.HasPrefix(k, "credential ")
	})
	if after := secrets(t); len(portable) < 2 || !maps.Equal(after, portable) {
		t.Fatalf("the secrets of the export do not open on host B (%d of %d)", len(after), len(portable))
	}
	if names := storedUsernames(t); strings.Contains(strings.Join(names, ","), "admin_b") {
		t.Fatalf("an account of host B survived the restore: %v", names)
	}
	if _, err := os.Lstat(filepath.Join(hostB, ".secret_key.tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary secret file left behind: %v", err)
	}
}

// fullArchive writes a Go archive of dir with every secret and the
// SECRET_KEY, as `migrate --replace` keeps one.
func fullArchive(t *testing.T, dir, secret string) string {
	t.Helper()
	material, err := keyring.LoadOrCreateMaterial(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName)
	db, err := store.Open(t.Context(), dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := legacy.StoredKeyID(t.Context(), db)
	if err = errors.Join(err, db.Close()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host-a-full.tar")
	if err := backup.WriteFile(path, backup.Contents{Database: dbPath, SecretKey: []byte(secret), Material: material,
		KeyID: keyID, Reason: backup.ReasonReplaced, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return path
}

// hostEnv is backupEnv with SECRET_KEY kept in DATA_DIR/secret_key, as the
// entrypoint does without the variable, and TOTP turned on.
func hostEnv(t *testing.T) map[string]string {
	t.Helper()
	env := backupEnv(t)
	delete(env, "SECRET_KEY")
	env["TOTP_ENABLED"] = "true"
	return env
}

// The online restore of host A's backup on host B through both servers:
// after the restart host B runs with host A's SECRET_KEY, and host A's
// administrator signs in with the password and the TOTP code of the
// authenticator enrolled on host A.
func TestOnlineRestoreOnAnotherHostKeepsSignInAndTOTP(t *testing.T) {
	envA, envB := hostEnv(t), hostEnv(t)
	sysA, tsA, stopA := openEnv(t, envA)
	const pwA, pwB = "admin-password-a1", "admin-password-b1"
	adminA := signUp(t, tsA.URL, "admin_a", pwA)
	key := enrollTOTP(t, sysA, adminA, tsA.URL, pwA)

	status, body := apiCall(t, adminA, tsA.URL, http.MethodPost, "/admin/api/backups", nil, totpGrant(t, adminA, tsA.URL, "backup.create", "new", key))
	if status != http.StatusAccepted {
		t.Fatalf("create on host A: %d %s", status, body)
	}
	id := decode(t, body)["operation_id"].(string)
	waitStatus(t, adminA, tsA.URL, id, "ready")
	code, archive := rawPost(t, adminA, tsA.URL, "/admin/api/backups/"+id+"/download", nil, totpGrant(t, adminA, tsA.URL, "backup.download", id, key))
	if code != http.StatusOK || len(archive) < 1024 {
		t.Fatalf("download from host A: %d %d bytes", code, len(archive))
	}
	secretA := readSecret(t, envA["DATA_DIR"])
	stopA()

	sysB, tsB, stopB := openEnv(t, envB)
	adminB := signUp(t, tsB.URL, "admin_b", pwB)
	if readSecret(t, envB["DATA_DIR"]) == secretA {
		t.Fatal("host B was set up with the secret of host A")
	}
	code, raw := rawPost(t, adminB, tsB.URL, "/admin/api/backups/upload", archive, adminGrant(t, adminB, tsB.URL, "backup.upload", "upload", pwB))
	if code != http.StatusAccepted {
		t.Fatalf("upload on host B: %d %s", code, raw)
	}
	up := decode(t, string(raw))["operation_id"].(string)
	waitStatus(t, adminB, tsB.URL, up, "verified")
	status, body = apiCall(t, adminB, tsB.URL, http.MethodPost, "/admin/api/backups/"+up+"/restore/prepare",
		map[string]any{"acknowledge_sensitive_restore": true}, adminGrant(t, adminB, tsB.URL, "backup.restore_prepare", up, pwB))
	if status != http.StatusOK {
		t.Fatalf("prepare on host B: %d %s", status, body)
	}
	token := decode(t, body)["confirmation_token"].(string)
	status, body = apiCall(t, adminB, tsB.URL, http.MethodPost, "/admin/api/backups/"+up+"/restore",
		map[string]any{"confirmation_token": token, "confirmation_phrase": "RESTORE", "confirm_destructive_restore": true},
		adminGrant(t, adminB, tsB.URL, "backup.restore", up, pwB))
	if status != http.StatusAccepted {
		t.Fatalf("restore on host B: %d %s", status, body)
	}
	select {
	case <-sysB.restart:
	case <-time.After(30 * time.Second):
		t.Fatal("no restart requested")
	}
	stopB()

	sysB, tsB, _ = openEnv(t, envB)
	if got := readSecret(t, envB["DATA_DIR"]); got != secretA || string(sysB.cfg.SecretKey.Bytes()) != secretA {
		t.Fatal("host B does not run with the SECRET_KEY of the archive")
	}
	if _, err := sysB.accounts.ByUsername(t.Context(), "admin_b"); err == nil {
		t.Fatal("the account of host B survived the restore")
	}
	c := signInTOTP(t, tsB.URL, "admin_a", pwA, key)
	if resp, page := get(t, c, tsB.URL+"/security"); resp.StatusCode != http.StatusOK || !csrfMeta.MatchString(page) {
		t.Fatalf("host A's administrator is not signed in on host B: %d", resp.StatusCode)
	}
	resp, st := get(t, c, tsB.URL+"/admin/api/backups/restore/status")
	if resp.StatusCode != http.StatusOK || decode(t, st)["state"] != "succeeded" {
		t.Fatalf("restore status: %d %s", resp.StatusCode, st)
	}
}

// enrollTOTP enrolls an authenticator for the signed-in administrator and
// turns MFA on; it returns the key.
func enrollTOTP(t *testing.T, sys *system, c *http.Client, base, password string) []byte {
	t.Helper()
	if err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO operations_feature_gates (feature, enabled) VALUES ('totp', 1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	status, body := apiCall(t, c, base, http.MethodPost, "/api/account/step-up/intents", map[string]string{"action": "totp.enroll"}, "")
	var intent struct {
		Intent string `json:"intent"`
		Grant  string `json:"grant"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &intent) != nil {
		t.Fatalf("intent: %d %s", status, body)
	}
	grant := intent.Grant
	if grant == "" {
		status, body = apiCall(t, c, base, http.MethodPost, "/api/account/step-up/password",
			map[string]string{"intent": intent.Intent, "password": password}, "")
		var g struct {
			Grant string `json:"grant"`
		}
		if status != http.StatusOK || json.Unmarshal([]byte(body), &g) != nil || g.Grant == "" {
			t.Fatalf("enroll step-up: %d %s", status, body)
		}
		grant = g.Grant
	}
	status, body = apiCall(t, c, base, http.MethodPost, "/api/totp/enroll", map[string]string{"label": "phone"}, grant)
	var enrollment struct {
		Token  string `json:"token"`
		Secret string `json:"secret"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &enrollment) != nil {
		t.Fatalf("enroll: %d %s", status, body)
	}
	key, err := otp.DecodeSecret(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	status, body = apiCall(t, c, base, http.MethodPost, "/api/totp/enroll/verify",
		map[string]any{"token": enrollment.Token, "code": totpCode(t, key, -1), "confirm_enable_mfa": true}, "")
	if status != http.StatusOK {
		t.Fatalf("activate: %d %s", status, body)
	}
	return key
}

// totpCode is the code of the current step plus offset.
func totpCode(t *testing.T, key []byte, offset int) string {
	t.Helper()
	step := otp.Step(time.Now(), otp.DefaultPeriod)
	c, err := otp.TOTP(key, uint64(int64(step)+int64(offset)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// totpGrant is adminGrant confirmed with a fresh TOTP code: every code is
// accepted once, so it waits for the next step.
func totpGrant(t *testing.T, c *http.Client, base, action, target string, key []byte) string {
	t.Helper()
	waitNextStep()
	status, body := apiCall(t, c, base, http.MethodPost, "/api/step-up/totp",
		map[string]string{"action": action, "target": target, "code": totpCode(t, key, 0)}, "")
	if status != http.StatusOK {
		t.Fatalf("TOTP step-up %s: %d %s", action, status, body)
	}
	return decode(t, body)["grant"].(string)
}

func waitNextStep() {
	start := otp.Step(time.Now(), otp.DefaultPeriod)
	for otp.Step(time.Now(), otp.DefaultPeriod) == start {
		time.Sleep(200 * time.Millisecond)
	}
}

// signInTOTP signs in with the password form and the TOTP factor.
func signInTOTP(t *testing.T, base, user, password string, key []byte) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	post := func(form url.Values) string {
		_, page := get(t, c, base+"/login")
		m := csrfField.FindStringSubmatch(page)
		if m == nil {
			t.Fatal("no CSRF token on /login")
		}
		form.Set("csrf_token", m[1])
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", base)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return string(raw)
	}
	page := post(url.Values{"username": {user}, "password": {password}})
	m := csrfField.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no CSRF token on the factor page")
	}
	waitNextStep()
	raw, _ := json.Marshal(map[string]string{"code": totpCode(t, key, 0)})
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/api/totp/auth/verify", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	req.Header.Set("X-CSRFToken", m[1])
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TOTP sign-in: %d %s", resp.StatusCode, out)
	}
	return c
}
