package accounts

import (
	"bufio"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

func retainedDirs(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestDeleteRetainsAVerifiedCopy(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "2026-01-01T00:00:00")
	l.exec(t, `INSERT INTO hostops_rows (user_id, v) VALUES (2, 'sealed-key-bytes'), (2, 'host'), (3, 'other')`)
	if err := l.s.Delete(t.Context(), principaltest.Admin(1), 2); err != nil {
		t.Fatal(err)
	}
	dirs := retainedDirs(t, l.retained)
	if len(dirs) != 1 || dirs[0] != "2-20261126T090000Z" {
		t.Fatalf("retained %v", dirs)
	}
	dir := filepath.Join(l.retained, dirs[0])
	if err := VerifyRetained(dir, 2); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{l.retained: 0o700, dir: 0o700, filepath.Join(dir, "manifest.json"): 0o600,
			filepath.Join(dir, "hostops_rows.jsonl"): 0o600, filepath.Join(dir, "accounts_users.jsonl"): 0o600} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != want {
				t.Errorf("%s: %v %v", path, info.Mode(), err)
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != RetainFormat || m.Username != "bob" || m.Incarnation != "2026-01-01T00:00:00" ||
		m.Tables["hostops_rows"].Rows != 2 || m.Tables["accounts_users"].Rows != 1 || m.Tables["session_sessions"].File != "" {
		t.Fatalf("manifest %+v", m)
	}
	f, err := os.Open(filepath.Join(dir, "hostops_rows.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var values []string
	for sc.Scan() {
		var row map[string]any
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil || row["user_id"] != float64(2) {
			t.Fatalf("row %s: %v", sc.Bytes(), err)
		}
		values = append(values, row["v"].(string))
	}
	if strings.Join(values, ",") != "sealed-key-bytes,host" {
		t.Fatalf("rows %v", values)
	}
	if w := l.audit.warnings; len(w) == 0 || w[len(w)-1] != "ADMIN_USER_DELETED" {
		t.Fatalf("audit %v", w)
	}
	// A changed copy no longer verifies.
	if err := os.WriteFile(filepath.Join(dir, "hostops_rows.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if VerifyRetained(dir, 2) == nil || VerifyRetained(dir, 3) == nil {
		t.Fatal("tampered copy verified")
	}
}

// Without a copy nothing is removed: the account stays (locked) with its rows.
func TestDeleteWithoutCopyRemovesNothing(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	if err := os.MkdirAll(filepath.Dir(l.retained), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.retained, nil, 0o600); err != nil { // the root is a file
		t.Fatal(err)
	}
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	l.exec(t, `INSERT INTO hostops_rows (user_id, v) VALUES (2, 'a')`)
	err := l.s.Delete(t.Context(), principaltest.Admin(1), 2)
	if _, _, msg := fault.Status(err); msg != "User deletion failed; the account remains locked" {
		t.Fatalf("%v", err)
	}
	if a := l.get(t, 2); !a.IsLocked || l.count(t, `SELECT count(*) FROM hostops_rows WHERE user_id = 2`) != 1 {
		t.Fatalf("%+v", a)
	}
	l.s.Retain = nil
	if err := l.s.Delete(t.Context(), principaltest.Admin(1), 2); fault.CodeOf(err) != fault.Internal {
		t.Fatalf("no retainer must fail closed: %v", err)
	}
}

// A deletion that fails after the copy removes the copy again.
func TestFailedDeletionDiscardsTheCopy(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	l.s.Data = failingData{}
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	if err := l.s.Delete(t.Context(), principaltest.Admin(1), 2); err == nil {
		t.Fatal("deletion succeeded")
	}
	if dirs := retainedDirs(t, l.retained); len(dirs) != 0 {
		t.Fatalf("copy of an account that still exists: %v", dirs)
	}
}
