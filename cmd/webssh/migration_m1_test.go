package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
)

const goldenLegacyDir = "../../tests/golden/fixture/legacy"

// extractGolden unpacks a legacy DATA_DIR of the golden data set.
func extractGolden(t *testing.T, archive string) string {
	t.Helper()
	f, err := os.Open(filepath.Join(goldenLegacyDir, archive))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dest := t.TempDir()
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		switch h.Typeflag {
		case tar.TypeDir:
			err = root.MkdirAll(name, 0o700)
		case tar.TypeReg:
			var out *os.File
			if out, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
				_, err = io.Copy(out, io.LimitReader(tr, h.Size))
				err = errors.Join(err, out.Close())
			}
		default:
			t.Fatalf("unexpected tar member %q", h.Name)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dest, "data")
}

func goldenSecret(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenLegacyDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		SecretKey struct {
			Value string `json:"value"`
		} `json:"secret_key"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.SecretKey.Value == "" {
		t.Fatalf("manifest secret: %v", err)
	}
	return m.SecretKey.Value
}

// The build's registry covers every entity, so the composition root
// migrates the extended golden data set; the persistent tmux sessions
// (A01) go to the terminal store with their legacy row ids instead of
// staying pending.
func TestBuildMigratesPersistentSessions(t *testing.T) {
	dir := extractGolden(t, "datadir-extended.tar")
	env := map[string]string{"DATA_DIR": dir, "SECRET_KEY": goldenSecret(t), "BACKUP_TEMP_DIR": t.TempDir()}
	lookup := func(name string) (string, bool) { v, ok := env[name]; return v, ok }
	log := slog.New(slog.DiscardHandler)
	cfg, err := bootstrapConfig(lookup, log)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := migrationRegistry(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if missing := reg.Uncovered(); len(missing) > 0 {
		t.Fatalf("uncovered entities %v", missing)
	}
	st, err := startMigration(t.Context(), cfg, lookup, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if !st.Migrated {
		t.Fatalf("state %s, not migrated", st.State)
	}
	for _, p := range st.Report.Pending {
		if p.Entity == "A01" {
			t.Fatalf("A01 pending: %+v", p)
		}
	}
	written := -1
	for _, e := range st.Report.Entities {
		if e.Entity == "A01" {
			written = e.Written
		}
	}
	if written <= 0 {
		t.Fatalf("A01 written %d", written)
	}
	db, err := store.Open(t.Context(), filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows []terminal.ImportedPersistent
	err = db.Read(t.Context(), func(tx *store.Tx) error {
		rows, err = terminal.ImportedPersistentTx(t.Context(), tx)
		return err
	})
	if err != nil || len(rows) != written {
		t.Fatalf("stored %d rows, report %d: %v", len(rows), written, err)
	}
	for _, r := range rows {
		if r.ID <= 0 || r.Row.Connected || r.Row.TmuxSessionName == "" {
			t.Errorf("row %+v", r)
		}
	}
}
