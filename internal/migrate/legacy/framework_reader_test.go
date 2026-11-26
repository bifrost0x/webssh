package legacy

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// K3/K10: the reader takes ssh_sessions over from the extended fixture
// (A01): persistent rows with their tmux names byte for byte, the other
// row counted as discarded.
func TestPersistentSessions(t *testing.T) {
	t.Parallel()
	src := openLegacy(t, extractLegacy(t, "datadir-extended.tar"))
	got, discarded, err := src.PersistentSessions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, s := range legacyFixture(t).Values.Extended.PersistentSessions {
		if s.IsPersistent && s.Tmux != nil {
			want = append(want, s.SessionID+"|"+*s.Tmux)
		}
	}
	var have []string
	for _, s := range got {
		have = append(have, s.SessionID+"|"+s.TmuxSessionName)
	}
	if !slices.Equal(have, want) || discarded != 1 {
		t.Fatalf("sessions %v (discarded %d), want %v", have, discarded, want)
	}
	if got[0].DisplayName.String != "Golden tmux ✓ 日本" || got[1].ViaJump.String != "bastion.golden.test" || got[1].AuthType != "key" {
		t.Errorf("fields: %+v", got)
	}
	// The release v1.0.0 wrote the table with fewer columns.
	old := openLegacy(t, extractLegacy(t, "datadir-v1.0.0.tar"))
	if s, _, err := old.PersistentSessions(t.Context()); err != nil || len(s) != 1 || s[0].TmuxSessionName != "webssh_pioneer_user_key_pioneer_test_2222_2edbfaeb" {
		t.Fatalf("v1.0.0: %+v, %v", s, err)
	}
}

// Columns Python adds later read with Python's defaults, including the
// auth_type rule for rows with a key.
func TestPersistentSessionsOldColumns(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := minimalDatabase(t, dir, false)
	execSQL(t, path, `CREATE TABLE ssh_sessions (id INTEGER PRIMARY KEY, session_id TEXT, user_id INTEGER, host TEXT, port INTEGER,
		username TEXT, connected BOOLEAN, created_at DATETIME, last_activity DATETIME, is_persistent BOOLEAN, key_id TEXT,
		tmux_session_name TEXT)`,
		`INSERT INTO ssh_sessions VALUES (1, 's1', 1, 'h', 22, 'u', 0, '2026-01-01 00:00:00', NULL, 1, 'k1', 'webssh_u_h_22_0011aabb')`,
		`INSERT INTO ssh_sessions VALUES (2, 's2', 1, 'h', 22, 'u', 0, NULL, NULL, 1, NULL, NULL)`)
	src, err := Open(t.Context(), dir, "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	got, discarded, err := src.PersistentSessions(t.Context())
	if err != nil || len(got) != 1 || discarded != 1 {
		t.Fatalf("%+v %d %v", got, discarded, err)
	}
	if got[0].AuthType != "key" || got[0].ViaSOCKS || got[0].DisplayName.Valid {
		t.Errorf("defaults: %+v", got[0])
	}
}

func TestRecoveryCheck(t *testing.T) {
	t.Parallel()
	want := "2026-11-02T10:00:40+00:00"
	src := openLegacy(t, extractLegacy(t, "datadir-extended.tar"))
	if rc, err := src.RecoveryCheck(); err != nil || rc.RestoredAt != want || rc.Malformed {
		t.Fatalf("extended: %+v, %v", rc, err)
	}
	for _, variant := range []string{"recovery_check_malformed", "recovery_check_oversized"} {
		dir := copyGolden(t)
		content, _ := base64.StdEncoding.DecodeString(legacyFixture(t).Variants[variant].Files["data/recovery-check.json"])
		if err := os.WriteFile(filepath.Join(dir, "recovery-check.json"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		src, err := Open(t.Context(), dir, "secret")
		if err != nil {
			t.Fatal(err)
		}
		rc, err := src.RecoveryCheck()
		src.Close()
		if err != nil || !rc.Present || !rc.Malformed || rc.RestoredAt != "" {
			t.Errorf("%s: %+v, %v", variant, rc, err)
		}
	}
	if rc, err := golden.source.RecoveryCheck(); err != nil || rc.Present {
		t.Errorf("no file: %+v, %v", rc, err)
	}
}

func TestParseRecoveryCheck(t *testing.T) {
	t.Parallel()
	long := strings.Repeat(" ", 460)
	for _, tt := range []struct {
		doc string
		ok  bool
	}{
		{`{"restored_at":"2026-11-02T10:00:40+00:00"}`, true},
		{`{"restored_at":"2026-11-02T10:00:40"}`, false}, // no offset
		{`{"restored_at":"2026-11-02T10:00:40Z"}`, true},
		{`{"restored_at":""}`, false},
		{`{"restored_at":1}`, false},
		{`{"restored_at":"x","restored_at":"2026-11-02T10:00:40+01:00"}`, true}, // json.loads keeps the last
		{`["2026-11-02T10:00:40+00:00"]`, false},
		{`{"restored_at":"2026-11-02T10:00:40+00:00"}` + long, true},
		{`{"restored_at":"2026-11-02T10:00:40+00:00"}` + long + strings.Repeat(" ", 30), false}, // over 512 characters
		{"{\"restored_at\":\"2026-11-02T10:00:40+00:00\"}" + strings.Repeat("\r\n", 460), true}, // CRLF counts once
		{"\xef\xbb\xbf{\"restored_at\":\"2026-11-02T10:00:40+00:00\"}", false},                  // BOM
	} {
		if _, ok := parseRecoveryCheck([]byte(tt.doc)); ok != tt.ok {
			t.Errorf("%.60q: ok = %v, want %v", tt.doc, ok, tt.ok)
		}
	}
	if got := pythonUTCISOFormat(time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)); got != "2026-11-26T08:00:00+00:00" {
		t.Error(got)
	}
	if got := pythonUTCISOFormat(time.Date(2026, 11, 26, 8, 0, 0, 1500, time.UTC)); got != "2026-11-26T08:00:00.000001+00:00" {
		t.Error(got)
	}
}

func FuzzParseRecoveryCheck(f *testing.F) {
	f.Add([]byte(`{"restored_at":"2026-11-02T10:00:40+00:00"}`))
	f.Add([]byte(`{"restored_at": `))
	f.Fuzz(func(t *testing.T, data []byte) {
		if at, ok := parseRecoveryCheck(data); ok && (at == "" || len([]rune(at)) > recoveryTimestampChars) {
			t.Fatalf("accepted %q", at)
		}
	})
}

func FuzzParseRestoreStatus(f *testing.F) {
	f.Add([]byte(`{"state":"succeeded","operation_id":"x","message":"m","updated_at":1}`))
	f.Add([]byte(`{"state":"in_progress","operation_id":"x","message":"m","updated_at":1,"data_fingerprint":"` + strings.Repeat("a", 64) + `","rollback_relative":"a/b"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if state, ok := parseRestoreStatus(data); ok && !slices.Contains(restoreStates, state) {
			t.Fatalf("accepted state %q", state)
		}
	})
}

// Section 5.6 step 3: Python's restore semantics on the recovery snapshot
// archive, which carries keys. An export restore drops remote
// credentials, raises every auth_generation, empties the transient tables
// and sets the recovery notice; a recovery snapshot keeps credentials.
func TestRestoreSemantics(t *testing.T) {
	t.Parallel()
	b, err := OpenBackup(backupPath("recovery_snapshot"), DefaultBackupLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	at := time.Date(2026, 11, 26, 9, 30, 0, 0, time.UTC)
	for _, mode := range []RestoreMode{RestoreExport, RestoreRecoverySnapshot} {
		dest := t.TempDir()
		res, err := ExtractBackup(b, dest, DefaultBackupLimits, mode)
		if err != nil {
			t.Fatal(err)
		}
		_, keysErr := os.Lstat(filepath.Join(dest, "users", "user_3", "keys"))
		if exported := mode == RestoreExport; exported != errors.Is(keysErr, os.ErrNotExist) {
			t.Errorf("mode %d: keys/ present = %v, %+v", mode, keysErr == nil, res)
		}
		src, err := Open(t.Context(), dest, golden.manifest.SecretKey.Value, PrivateCopy(), Restored(mode, at))
		if err != nil {
			t.Fatal(err)
		}
		users, err := src.Users(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range users {
			for name, want := range golden.manifest.Values.Users {
				if want.ID == u.ID && u.AuthGeneration != want.AuthGeneration+1 {
					t.Errorf("%s: auth_generation %d, want %d", name, u.AuthGeneration, want.AuthGeneration+1)
				}
			}
		}
		tables, _ := src.Tables(t.Context())
		if tables["ssh_sessions"] != 0 || tables["authentication_sessions"] != 0 {
			t.Errorf("transient tables: %v", tables)
		}
		rc, _ := src.RecoveryCheck()
		if (mode == RestoreExport) != (rc.RestoredAt == "2026-11-26T09:30:00+00:00") {
			t.Errorf("mode %d: recovery check %+v", mode, rc)
		}
		src.Close()
	}
}

// K3 R3: the filter for go/, logs/ and Python's runtime directories in
// ExtractBackup ignores case and trailing dots and spaces, as Python does.
func TestRestoreSkipFoldsNames(t *testing.T) {
	t.Parallel()
	var res ExtractResult
	for _, name := range []string{"go/webssh.db", "GO/webssh.db", "Go./x", "LOGS/app.log", "logs /a", "TMP/x", ".Access-Revocations/1"} {
		if restoreSkip(&res, name, RestoreRecoverySnapshot) == nil {
			t.Errorf("%s is restored", name)
		}
	}
	for _, name := range []string{"gopher/x", "users/user_3/go/x", "app.db"} {
		if restoreSkip(&res, name, RestoreRecoverySnapshot) != nil {
			t.Errorf("%s is dropped", name)
		}
	}
	for name, dropped := range map[string]bool{
		"users/user_3/keys/a.pem": true, "deleted_users/user_1_x/p.json": true, "users/user_3/credentials.json": true,
		"users/user_3/.credentials.json.tmp": true, "users/user_3/automation-vault.json.bak": true,
		"users/user_3/Keys/a.pem": false, "users/user_3/credentials.json5": false,
	} {
		if got := restoreSkip(&res, name, RestoreExport) != nil; got != dropped {
			t.Errorf("export %s: dropped %v, want %v", name, got, dropped)
		}
	}
}
