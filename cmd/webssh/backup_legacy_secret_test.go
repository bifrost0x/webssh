package main

import (
	"encoding/hex"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
)

// pythonSecrets prints a digest of every secret the Python release opens
// in a DATA_DIR (SSH keys, TOTP secrets) together with what pythonView
// shows: the way back to Python reads the same data with the same key.
const pythonSecrets = pythonView + `
import hashlib
with app.app_context():
    from app.models import User, TOTPAuthenticator
    from app import key_manager
    from app.mfa_crypto import decrypt_totp_secret
    seen = {}
    for u in User.query.order_by(User.id).all():
        for k in key_manager.load_keys(str(u.id)):
            content, err = key_manager.read_key_content(str(u.id), k['id'])
            seen['key %s %s' % (u.id, k['id'])] = err or hashlib.sha256(content.encode()).hexdigest()
    for a in TOTPAuthenticator.query.order_by(TOTPAuthenticator.id).all():
        seen['totp %s' % a.id] = hashlib.sha256(decrypt_totp_secret(a.user_id, a.encrypted_secret).encode()).hexdigest()
sys.stdout.write("\n--secrets--\n" + json.dumps(seen, sort_keys=True))
`

// legacyOnly is legacyState without the Go-owned paths.
func legacyOnly(t *testing.T, dir string) map[string]legacyFile {
	t.Helper()
	st := legacyState(t, dir)
	maps.DeleteFunc(st, func(rel string, _ legacyFile) bool {
		for _, p := range []string{keyring.GoDirName, filepath.Join(keyring.LogsDirName, keyring.StateDirName)} {
			if rel == p || strings.HasPrefix(rel, p+string(filepath.Separator)) {
				return true
			}
		}
		return false
	})
	return st
}

// migratedBesideLegacy is the extended golden data set migrated by Go
// with the legacy source kept (S2), the commands pointed at it.
func migratedBesideLegacy(t *testing.T) string {
	t.Helper()
	dir := extractGolden(t, "datadir-extended.tar")
	rotationEnv(t, dir)
	g, err := openCommandDataMigrating(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// rotatedArchive is a Go archive of a purged installation with another
// SECRET_KEY than the golden data set, and every secret it opens.
func rotatedArchive(t *testing.T) (string, string, map[string]string) {
	t.Helper()
	dir := migratedPurged(t)
	if out := runCLI(t, "rotate-secret-key", "--confirm-offline"); out.Code != 0 {
		t.Fatalf("rotation on host A: %+v", out)
	}
	secret := readSecret(t, dir)
	return fullArchive(t, dir, secret), secret, secrets(t)
}

// nextState is the state the next start finds.
func nextState(t *testing.T) legacy.State {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	st, err := startMigration(t.Context(), cfg, os.LookupEnv, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("next start: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if st.Migrated {
		t.Fatal("the next start migrated again")
	}
	return st.State
}

func runPython(t *testing.T, python, script, dir, secret string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), python, "-c", script)
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "DATA_DIR="+dir, "SECRET_KEY="+secret, "PYTHONPATH=.", "PYTHONDONTWRITEBYTECODE=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("python: %v\n%s%s", err, raw, stderr.String())
	}
	_, out, ok := strings.Cut(string(raw), "\n--result--\n")
	if !ok {
		t.Fatalf("python output: %s", raw)
	}
	// The release logs JSON lines to stdout as well.
	return pythonLogLine.ReplaceAllString(out, "")
}

var pythonLogLine = regexp.MustCompile(`\{"timestamp": "[^\n]*(\n|$)`)

// RS4-01: a Go archive made with another SECRET_KEY, restored on a
// migrated installation whose legacy source still exists, never writes
// DATA_DIR/secret_key (migration specification 4.9): its secrets are
// resealed under the active SECRET_KEY and keyring material. Every legacy
// file stays byte for byte, the next start is S2 (not S3 legacy_changed),
// every secret of the archive opens under the active key, and the
// Python release still opens its own data on the way back.
func TestRestoreBesideLegacyDataKeepsTheSecret(t *testing.T) {
	archive, secretA, want := rotatedArchive(t)
	if len(want) < 5 || want["github"] == "" {
		t.Fatalf("the archive holds too few secrets: %d", len(want))
	}
	hostB := migratedBesideLegacy(t)
	secretB := readSecret(t, hostB)
	if secretA == secretB {
		t.Fatal("host A kept the golden secret")
	}
	before := legacyOnly(t, hostB)
	materialPath, materialBefore, err := keyring.MaterialLocation(hostB, true)
	if err != nil || materialBefore == nil {
		t.Fatalf("material of host B: %v", err)
	}

	if out := runCLI(t, "backup", "restore", archive, "--confirm-offline"); out.Code != 0 {
		t.Fatalf("restore: %+v", out)
	}
	if got := readSecret(t, hostB); got != secretB {
		t.Fatal("DATA_DIR/secret_key rewritten while the legacy source exists")
	}
	assertLegacyUnchanged(t, hostB, before)
	if raw, err := os.ReadFile(materialPath); err != nil || hex.EncodeToString(raw) != hex.EncodeToString(materialBefore) { // #nosec G304 -- test data
		t.Fatalf("the keyring material changed: %v", err)
	}
	if st := nextState(t); st != legacy.S2 {
		t.Fatalf("next start: %s, want S2", st)
	}
	if got := secrets(t); !maps.Equal(got, want) {
		t.Fatalf("the archive's secrets do not open under the active key (%d of %d)", len(got), len(want))
	}
	if names := storedUsernames(t); len(names) == 0 {
		t.Fatal("no account restored")
	}
	assertLegacyUnchanged(t, hostB, before)

	// The way back: the Python release opens its data with secret_key.
	python := pythonBinary(t)
	pristine := extractGolden(t, "datadir-extended.tar")
	if got, ref := runPython(t, python, pythonSecrets, hostB, secretB), runPython(t, python, pythonSecrets, pristine, secretB); got != ref {
		t.Fatalf("the Python release reads other data after the restore:\n got %s\nwant %s", got, ref)
	}
}

// The online server signs in host A's administrator with password and
// TOTP after a Go archive of host A was restored beside host B's legacy
// data, and keeps host B's SECRET_KEY. (The server appends to
// logs/security_audit.log afterwards, E34.)
func TestRestoreBesideLegacyDataKeepsSignInAndTOTP(t *testing.T) {
	envA := hostEnv(t)
	sysA, tsA, stopA := openEnv(t, envA)
	const pwA = "admin-password-a1"
	adminA := signUp(t, tsA.URL, "admin_a", pwA)
	key := enrollTOTP(t, sysA, adminA, tsA.URL, pwA)
	status, body := apiCall(t, adminA, tsA.URL, http.MethodPost, "/admin/api/backups", nil, totpGrant(t, adminA, tsA.URL, "backup.create", "new", key))
	if status != http.StatusAccepted {
		t.Fatalf("create on host A: %d %s", status, body)
	}
	id := decode(t, body)["operation_id"].(string)
	waitStatus(t, adminA, tsA.URL, id, "ready")
	code, raw := rawPost(t, adminA, tsA.URL, "/admin/api/backups/"+id+"/download", nil, totpGrant(t, adminA, tsA.URL, "backup.download", id, key))
	if code != http.StatusOK {
		t.Fatalf("download from host A: %d", code)
	}
	stopA()
	archive := filepath.Join(t.TempDir(), "host-a.tar")
	if err := os.WriteFile(archive, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	hostB := migratedBesideLegacy(t)
	secretB := readSecret(t, hostB)
	before := legacyOnly(t, hostB)
	if out := runCLI(t, "backup", "restore", archive, "--confirm-offline"); out.Code != 0 {
		t.Fatalf("restore: %+v", out)
	}
	assertLegacyUnchanged(t, hostB, before)
	envB := hostEnv(t)
	envB["DATA_DIR"] = hostB
	sysB, tsB, _ := openEnv(t, envB)
	if string(sysB.cfg.SecretKey.Bytes()) != secretB || readSecret(t, hostB) != secretB {
		t.Fatal("host B does not keep its SECRET_KEY")
	}
	c := signInTOTP(t, tsB.URL, "admin_a", pwA, key)
	if resp, page := get(t, c, tsB.URL+"/security"); resp.StatusCode != http.StatusOK || !csrfMeta.MatchString(page) {
		t.Fatalf("host A's administrator is not signed in on host B: %d", resp.StatusCode)
	}
}
