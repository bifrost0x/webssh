package legacy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/platform"
	"github.com/bifrost0x/webssh/internal/store"
)

// H1: the data directory as the entrypoint and platform.PrepareDataDir
// leave it (empty logs/ and keys/) is no legacy source: a new installation
// is S0, a Go-native database beside it S2, and legacy data removed after
// a migration S5.
func TestPreparedDataDirIsNoLegacySource(t *testing.T) {
	t.Parallel()
	prepare := func(t *testing.T, dir string) {
		t.Helper()
		if _, err := platform.PrepareDataDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("fresh", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		prepare(t, dir)
		if st, err := startClosed(testOptions(t, dir)); err != nil || st.State != S0 {
			t.Fatalf("%+v, %v", st, err)
		}
	})
	t.Run("go-native database", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		prepare(t, dir)
		material, err := keyring.LoadOrCreateMaterial(dir, false)
		if err != nil {
			t.Fatal(err)
		}
		ring, err := keyring.Open([]byte(golden.manifest.SecretKey.Value), material)
		if err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(t.Context(), filepath.Join(dir, "go", "webssh.db"), store.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.ApplyAll(t.Context(), RecordSchema()); err != nil {
			t.Fatal(err)
		}
		if err := RecordKeyID(t.Context(), db, ring.KeyID()); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if st, err := startClosed(testOptions(t, dir)); err != nil || st.State != S2 {
			t.Fatalf("%+v, %v", st, err)
		}
	})
	t.Run("legacy removed", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		o := testOptions(t, dir)
		if _, err := startClosed(o); err != nil {
			t.Fatal(err)
		}
		for _, name := range append(legacyIndicators, "app.db", "secret_key") {
			_ = os.RemoveAll(filepath.Join(dir, name))
		}
		prepare(t, dir)
		if st, err := startClosed(o); err != nil || st.State != S5 {
			t.Fatalf("%+v, %v", st, err)
		}
	})
	t.Run("empty user directories", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		prepare(t, dir)
		if err := os.MkdirAll(filepath.Join(dir, "users", "user_1", "keys"), 0o700); err != nil {
			t.Fatal(err)
		}
		if st, err := startClosed(testOptions(t, dir)); err != nil || st.State != S0 {
			t.Fatalf("%+v, %v", st, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "users", "user_1", "keys", "keys.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := startClosed(testOptions(t, dir)); stopCode(err) != CodeLegacyUnknown {
			t.Fatalf("a file under users/ without app.db: %v", err)
		}
	})
}
