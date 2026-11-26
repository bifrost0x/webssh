package store_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/auth/ldap"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/auth/oidc"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/auth/webauthn"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/jobs"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
	"github.com/bifrost0x/webssh/internal/vault"
)

// productionSchemas lists the schema of every capability that has one.
// A capability that adds a schema adds it here.
func productionSchemas() []store.Schema {
	return []store.Schema{
		accounts.Schema(),
		auth.Schema(),
		local.Schema(),
		stepup.Schema(),
		totp.Schema(),
		operations.Schema(),
		session.Schema(),
		hostkey.Schema(),
		hosts.Schema(),
		hostops.Schema(),
		vault.Schema(),
		settings.Schema(),
		legacy.RecordSchema(),
		webauthn.Schema(),
		terminal.Schema(),
		jobs.Schema(),
		ldap.Schema(),
		github.Schema(),
		oidc.Schema(),
	}
}

// Every owner registers exactly one ordered migration list. Two lists for
// the same owner (two packages building in "auth", for example) make the
// second Apply see a foreign checksum at version 1 and refuse to start.
func TestProductionSchemasApplyTogether(t *testing.T) {
	schemas := productionSchemas()
	var owners []string
	for _, s := range schemas {
		if slices.Contains(owners, s.Owner) {
			t.Fatalf("owner %q registers more than one migration list", s.Owner)
		}
		owners = append(owners, s.Owner)
	}
	path := filepath.Join(t.TempDir(), "webssh.db")
	for round := range 2 {
		db, err := store.Open(t.Context(), path, store.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.ApplyAll(t.Context(), schemas...); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// The pending sign-ins and the second-factor state share the owner auth;
// their tables come from one list, in order.
func TestAuthSchemaIsOneOrderedList(t *testing.T) {
	s := auth.Schema()
	if s.Owner != "auth" {
		t.Fatalf("owner %q", s.Owner)
	}
	for i, m := range s.Migrations {
		if m.Version != i+1 {
			t.Fatalf("migration %d has version %d", i+1, m.Version)
		}
	}
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "webssh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.ApplyAll(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"auth_pending", "auth_recovery_codes", "auth_mfa_throttle"} {
		var n int
		if err := db.Read(t.Context(), func(tx *store.Tx) error {
			return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("table %s missing", table)
		}
	}
	// A second list for the same owner is refused, which is what the
	// single list prevents.
	split := store.Schema{Owner: "auth", Migrations: s.Migrations[1:]}
	split.Migrations = []store.Migration{{Version: 1, SQL: split.Migrations[0].SQL}}
	if err := db.ApplyAll(t.Context(), split); err == nil {
		t.Fatal("a second auth list was applied")
	}
}

// productionSchemas misses no schema: every non-test source file that
// declares one is counted.
func TestProductionSchemasAreComplete(t *testing.T) {
	declared := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		declared += strings.Count(string(src), "store.Schema{Owner:")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(productionSchemas()); got != declared {
		t.Fatalf("productionSchemas lists %d schemas, the sources declare %d", got, declared)
	}
}
