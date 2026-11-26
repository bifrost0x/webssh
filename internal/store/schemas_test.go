package store_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
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
