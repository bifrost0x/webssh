package legacy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// testKeysStep migrates the SSH keys of every account into a test table,
// sealed with the keyring, and verifies them by opening each one again.
// It stands in for the real step of E23 (D2) and exercises the whole path:
// legacy decryption, sealing, verification.
type testKeysStep struct {
	keys []testKey
}

type testKey struct {
	user int64
	key  SSHKey
}

var testSchema = store.Schema{Owner: "hostops", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE hostops_c7_keys (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, sealed BLOB NOT NULL) STRICT;
CREATE TABLE hostops_c7_sessions (session_id TEXT PRIMARY KEY, tmux TEXT NOT NULL, display TEXT) STRICT`}}}

func (*testKeysStep) Entity() string { return "E23" }
func (*testKeysStep) Version() int   { return 1 }

func (s *testKeysStep) Read(_ context.Context, src *Source) error {
	dirs, err := src.UserDirectories()
	if err != nil {
		return err
	}
	for _, d := range dirs {
		id, err := strconv.ParseInt(strings.TrimPrefix(d, "user_"), 10, 64)
		if err != nil {
			continue
		}
		store, err := src.SSHKeys(id)
		if err != nil {
			return &StepError{UserID: id, Err: err}
		}
		for _, k := range store.Keys {
			s.keys = append(s.keys, testKey{user: id, key: k})
		}
	}
	return nil
}

func keyAAD(id string) keyring.AAD {
	return keyring.AAD{Table: "hostops_c7_keys", Column: "sealed", Row: id}
}

func (s *testKeysStep) Write(ctx context.Context, tx *store.Tx, seal Sealer) error {
	for _, k := range s.keys {
		sealed, err := seal.Seal(keyring.SSHKey, keyAAD(k.key.ID), k.key.PEM)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO hostops_c7_keys VALUES (?, ?, ?)`, k.key.ID, k.user, sealed); err != nil {
			return &StepError{UserID: k.user, Record: k.key.ID, Err: err}
		}
	}
	return nil
}

func (s *testKeysStep) Verify(ctx context.Context, tx *store.Tx, open Opener) error {
	for _, k := range s.keys {
		var sealed []byte
		if err := tx.QueryRowContext(ctx, `SELECT sealed FROM hostops_c7_keys WHERE id = ?`, k.key.ID).Scan(&sealed); err != nil {
			return err
		}
		plain, err := open.Open(keyring.SSHKey, keyAAD(k.key.ID), sealed)
		if err != nil || !bytes.Equal(plain, k.key.PEM) {
			return &StepError{UserID: k.user, Record: k.key.ID, Err: errors.New("key does not read back")}
		}
	}
	return nil
}

func (s *testKeysStep) Report() StepReport {
	return StepReport{Entity: "E23", Version: 1, Read: len(s.keys), Written: len(s.keys)}
}

// testSessionsStep copies the persistent tmux sessions (A01).
type testSessionsStep struct {
	sessions  []PersistentSession
	discarded int
}

func (*testSessionsStep) Entity() string { return "A01" }
func (*testSessionsStep) Version() int   { return 1 }

func (s *testSessionsStep) Read(ctx context.Context, src *Source) (err error) {
	s.sessions, s.discarded, err = src.PersistentSessions(ctx)
	return err
}

func (s *testSessionsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, p := range s.sessions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hostops_c7_sessions VALUES (?, ?, ?)`, p.SessionID, p.TmuxSessionName, p.DisplayName); err != nil {
			return err
		}
	}
	return nil
}

func (s *testSessionsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hostops_c7_sessions`).Scan(&n); err != nil || n != len(s.sessions) {
		return fmt.Errorf("sessions: %d rows, want %d (%v)", n, len(s.sessions), err)
	}
	return nil
}

func (s *testSessionsStep) Report() StepReport {
	return StepReport{Entity: "A01", Version: 1, Read: len(s.sessions), Written: len(s.sessions), Discarded: s.discarded}
}

// testRegistry is a registry with E35, the two test steps and pending
// entities.
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	r.Schemas(testSchema)
	for _, err := range []error{
		AddSingleUserStores(r),
		r.Add(GroupKeys, func() Step { return &testKeysStep{} }),
		r.Add(GroupTerminal, func() Step { return &testSessionsStep{} }),
		r.KeepInPlace("E29", "B6", func(_ context.Context, src *Source) (int, error) {
			dirs, err := src.UserDirectories()
			return len(dirs), err
		}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func testOptions(t *testing.T, dataDir string) Options {
	t.Helper()
	return Options{
		DataDir: dataDir, Secret: golden.manifest.SecretKey.Value, SecretSource: "file", Release: "test",
		Registry: testRegistry(t), BackupTempDir: filepath.Join(t.TempDir(), "backup-ops"),
	}
}

// entryState is what I-01 checks for one legacy path.
type entryState struct {
	dir     bool
	mode    fs.FileMode
	size    int64
	mtimeNS int64
	sha     string
}

// goOwned reports the Go-owned paths of section 2: go/ and
// logs/.webssh-go/ with everything below them. logs/ itself may be
// created, as the entrypoint does.
func goOwned(rel string) bool {
	return rel == "go" || strings.HasPrefix(rel, "go/") || rel == "logs" ||
		rel == "logs/.webssh-go" || strings.HasPrefix(rel, "logs/.webssh-go/")
}

// legacySnapshot records every path of dataDir outside the Go-owned paths:
// content hash, size, mode and mtime of files, existence and mode of
// directories (I-01, I-19).
func legacySnapshot(t *testing.T, dataDir string) map[string]entryState {
	t.Helper()
	out := map[string]entryState{}
	err := filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dataDir, p)
		rel = filepath.ToSlash(rel)
		if rel == "." || goOwned(rel) {
			return nil
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := entryState{dir: d.IsDir(), mode: info.Mode()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			st.size, st.mtimeNS, st.sha = info.Size(), info.ModTime().UnixNano(), hex.EncodeToString(sum[:])
		}
		out[rel] = st
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// assertUntouched checks I-01 and I-19 against an earlier snapshot.
func assertUntouched(t *testing.T, dataDir string, before map[string]entryState) {
	t.Helper()
	after := legacySnapshot(t, dataDir)
	for p, b := range before {
		a, ok := after[p]
		switch {
		case !ok:
			t.Errorf("I-01: %s was removed", p)
		case a != b:
			t.Errorf("I-01: %s changed: %+v, was %+v", p, a, b)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("I-19: %s was created outside the Go-owned paths", p)
		}
	}
}

// assertRegularOnly checks that go/ holds only regular files and
// directories (I-18).
func assertRegularOnly(t *testing.T, dataDir string) {
	t.Helper()
	_ = filepath.WalkDir(filepath.Join(dataDir, "go"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !d.Type().IsRegular() {
			t.Errorf("I-18: %s is not a regular file", p)
		}
		return nil
	})
}

func stopCode(err error) string {
	if se, ok := errors.AsType[*StopError](err); ok {
		return se.Code
	}
	return ""
}

func mustStart(t *testing.T, o Options) *Startup {
	t.Helper()
	st, err := Start(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// startClosed runs Start and releases the lock at once.
func startClosed(o Options) (*Startup, error) {
	st, err := Start(context.Background(), o)
	if err == nil {
		err = st.Close()
	}
	return st, err
}

// touchLegacy changes one legacy file as a running Python release would.
func touchLegacy(t *testing.T, dataDir string) {
	t.Helper()
	p := filepath.Join(dataDir, "session_epoch")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Second)
	_ = os.Chtimes(p, later, later)
}

func mustLayout(t *testing.T, dir string) layout {
	t.Helper()
	l, err := layoutOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
