package backup

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

var keyIDSchema = store.Schema{Owner: "migrate", Migrations: []store.Migration{{Version: 1,
	SQL: `CREATE TABLE migrate_keyring (id INTEGER PRIMARY KEY, key_id TEXT NOT NULL) STRICT;
CREATE TABLE migrate_other (id INTEGER PRIMARY KEY, sealed BLOB) STRICT`}}}

func writeKeyID(ctx context.Context, tx *store.Tx, id string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO migrate_keyring (id, key_id) VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET key_id = excluded.key_id`, id)
	return err
}

func storedKeyID(ctx context.Context, db *store.DB) (string, error) {
	var id string
	err := db.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT key_id FROM migrate_keyring WHERE id = 1`).Scan(&id)
	})
	return id, err
}

var probeStep = RotationStep{Name: "probe", Run: func(ctx context.Context, tx *store.Tx, rt *keyring.Rotation) (int, error) {
	var sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT sealed FROM vault_probe WHERE id = '1'`).Scan(&sealed); err != nil {
		return 0, err
	}
	out, err := rt.Reseal(keyring.SSHKey, probeAAD(), sealed)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE vault_probe SET sealed = ? WHERE id = '1'`, out)
	return 1, err
}}

type rotationFixture struct {
	dataDir  string
	db       *store.DB
	secret   []byte
	material []byte
	ring     *keyring.Ring
}

// newRotationFixture is a data directory with DATA_DIR/secret_key, a Go
// database with one sealed record and the key identifier.
func newRotationFixture(t *testing.T) rotationFixture {
	t.Helper()
	f := rotationFixture{dataDir: t.TempDir(), secret: []byte("rotation-test-secret-0123456789"), material: make([]byte, keyring.MaterialSize)}
	_, _ = rand.Read(f.material)
	var err error
	if f.ring, err = keyring.Open(f.secret, f.material); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.dataDir, keyring.GoDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installSecretFile(filepath.Join(f.dataDir, secretFileName), f.secret); err != nil {
		t.Fatal(err)
	}
	f.db, err = store.Open(t.Context(), filepath.Join(f.dataDir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Close() })
	sealed, err := f.ring.Seal(keyring.SSHKey, probeAAD(), []byte("private key"))
	if err == nil {
		err = f.db.ApplyAll(t.Context(), probeSchema, keyIDSchema)
	}
	if err == nil {
		err = f.db.Write(t.Context(), func(tx *store.Tx) error {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO vault_probe VALUES ('1', ?)`, sealed); err != nil {
				return err
			}
			return writeKeyID(t.Context(), tx, f.ring.KeyID())
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f rotationFixture) request() RotateRequest {
	return RotateRequest{DataDir: f.dataDir, DB: f.db, Ring: f.ring, Material: f.material, LegacyPurged: true,
		Steps: []RotationStep{probeStep}, WriteKeyID: writeKeyID}
}

func (f rotationFixture) pending() string {
	return filepath.Join(f.dataDir, keyring.GoDirName, PendingSecretName)
}

func TestRotateSecret(t *testing.T) {
	f := newRotationFixture(t)
	out, err := RotateSecret(t.Context(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := readSecretFile(filepath.Join(f.dataDir, secretFileName))
	if err != nil || len(secret) != 64 {
		t.Fatalf("secret %q: %v", secret, err)
	}
	ring, err := keyring.Open(secret, f.material)
	if err != nil {
		t.Fatal(err)
	}
	if stored, _ := storedKeyID(t.Context(), f.db); stored != ring.KeyID() || out.KeyID != stored || out.Counts["probe"] != 1 {
		t.Fatalf("stored %s, ring %s, out %+v", stored, ring.KeyID(), out)
	}
	err = f.db.Read(t.Context(), func(tx *store.Tx) error {
		ok, err := probe(t.Context(), tx, ring)
		if !ok {
			return errors.New("no probe")
		}
		return err
	})
	if err != nil {
		t.Fatalf("the record does not open under the new key: %v", err)
	}
	if _, err := os.Lstat(f.pending()); !os.IsNotExist(err) {
		t.Fatalf("pending secret left: %v", err)
	}
	info, err := os.Stat(filepath.Join(f.dataDir, secretFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode: %v %v", info, err)
	}
}

// A sealed column that no step handles stops the rotation with nothing
// changed.
func TestRotateSecretRefusesLeftovers(t *testing.T) {
	f := newRotationFixture(t)
	other, err := f.ring.Seal(keyring.TOTP, keyring.AAD{Table: "migrate_other", Column: "sealed", Row: "1"}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO migrate_other VALUES (1, ?)`, other)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateSecret(t.Context(), f.request()); !errors.Is(err, ErrRotationLeftover) {
		t.Fatalf("leftover: %v", err)
	}
	f.assertUnchanged(t)
}

func (f rotationFixture) assertUnchanged(t *testing.T) {
	t.Helper()
	if stored, _ := storedKeyID(t.Context(), f.db); stored != f.ring.KeyID() {
		t.Fatal("the key identifier changed")
	}
	if secret, _ := readSecretFile(filepath.Join(f.dataDir, secretFileName)); string(secret) != string(f.secret) {
		t.Fatal("the secret file changed")
	}
	if _, err := os.Lstat(f.pending()); !os.IsNotExist(err) {
		t.Fatalf("pending secret left: %v", err)
	}
	err := f.db.Read(t.Context(), func(tx *store.Tx) error {
		_, err := probe(t.Context(), tx, f.ring)
		return err
	})
	if err != nil {
		t.Fatalf("the record no longer opens under the old key: %v", err)
	}
}

func TestRotateSecretRefusals(t *testing.T) {
	f := newRotationFixture(t)
	r := f.request()
	r.LegacyPurged = false
	if _, err := RotateSecret(t.Context(), r); !errors.Is(err, keyring.ErrRotationLegacy) {
		t.Fatalf("legacy data: %v", err)
	}
	r = f.request()
	r.NewSecret = f.secret
	if _, err := RotateSecret(t.Context(), r); !errors.Is(err, keyring.ErrRotationSameKey) {
		t.Fatalf("same secret: %v", err)
	}
	for _, bad := range []string{"a\nb", "a\rb", "a\x00b"} {
		r = f.request()
		r.NewSecret = []byte(bad)
		if _, err := RotateSecret(t.Context(), r); err == nil {
			t.Fatalf("secret %q accepted", bad)
		}
	}
	r = f.request()
	r.Steps = []RotationStep{{Name: "failing", Run: func(context.Context, *store.Tx, *keyring.Rotation) (int, error) {
		return 0, errors.New("boom")
	}}}
	if _, err := RotateSecret(t.Context(), r); err == nil {
		t.Fatal("a failing step committed")
	}
	if _, err := RotateSecret(t.Context(), RotateRequest{}); err == nil {
		t.Fatal("an empty request ran")
	}
	f.assertUnchanged(t)
	// A link in place of the pending secret is refused, not followed.
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, f.pending()); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateSecret(t.Context(), f.request()); !errors.Is(err, errSecretFile) {
		t.Fatalf("symlink: %v", err)
	}
	if raw, _ := os.ReadFile(target); string(raw) != "x\n" {
		t.Fatal("the link target changed")
	}
}

// CompleteRotation installs a committed pending secret and leaves one
// that never committed; DiscardStaleRotation removes the latter.
func TestCompleteRotation(t *testing.T) {
	f := newRotationFixture(t)
	material := func() ([]byte, error) { return f.material, nil }
	keyID := func() (string, error) { return storedKeyID(t.Context(), f.db) }
	if done, err := CompleteRotation(f.dataDir, material, keyID); done || err != nil {
		t.Fatalf("without a pending secret: %t %v", done, err)
	}
	// A rotation that wrote its pending secret and stopped.
	stale := []byte("stale-secret-0123456789abcdef")
	if err := installSecretFile(f.pending(), stale); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteRotation(f.dataDir, material, keyID); done || err != nil {
		t.Fatalf("uncommitted: %t %v", done, err)
	}
	if _, err := os.Lstat(f.pending()); err != nil {
		t.Fatal("CompleteRotation removed a pending secret")
	}
	if err := DiscardStaleRotation(f.dataDir, f.ring, f.ring.KeyID()); err != nil {
		t.Fatal(err)
	}
	f.assertUnchanged(t)
	// A rotation that committed and stopped before installing.
	r := f.request()
	r.Checkpoint = func(p string) {
		if p == PointCommitted {
			panic("crash")
		}
	}
	func() {
		defer func() { _ = recover() }()
		_, _ = RotateSecret(t.Context(), r)
	}()
	pendingSecret, err := readSecretFile(f.pending())
	if err != nil || pendingSecret == nil {
		t.Fatalf("pending secret after the commit: %v", err)
	}
	newRing, err := keyring.Open(pendingSecret, f.material)
	if err != nil {
		t.Fatal(err)
	}
	// The stale check keeps it: the database is under the new key.
	if err := DiscardStaleRotation(f.dataDir, f.ring, newRing.KeyID()); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteRotation(f.dataDir, material, keyID); !done || err != nil {
		t.Fatalf("committed: %t %v", done, err)
	}
	if secret, _ := readSecretFile(filepath.Join(f.dataDir, secretFileName)); string(secret) != string(pendingSecret) {
		t.Fatal("the committed secret was not installed")
	}
	if _, err := os.Lstat(f.pending()); !os.IsNotExist(err) {
		t.Fatalf("pending secret left: %v", err)
	}
}

func FuzzReadSecretFile(f *testing.F) {
	f.Add([]byte("secret\n"))
	f.Add([]byte("a\r\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := filepath.Join(t.TempDir(), "s")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := readSecretFile(p)
		if err != nil {
			return
		}
		if checkSecret(s) != nil || string(s)+"\n" != string(raw) && string(s) != string(raw) {
			t.Fatalf("read %q from %q", s, raw)
		}
	})
}
