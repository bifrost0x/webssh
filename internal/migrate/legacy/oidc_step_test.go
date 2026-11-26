package legacy

import (
	"errors"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/oidc"
)

// oidcOptions is the M1 registry with the E05 step of the OIDC build;
// wrap decorates the E05 step (failure and crash injection).
func oidcOptions(t *testing.T, dir string, wrap func(Step) Step) Options {
	t.Helper()
	o := testOptions(t, dir)
	r := m1Registry(t, M1{})
	if wrap == nil {
		if err := AddOIDCIdentities(r); err != nil {
			t.Fatal(err)
		}
	} else {
		r.Schemas(oidc.Schema())
		if err := r.TakeOver(GroupAccounts, func() Step { return wrap(&oidcIdentitiesStep{}) }); err != nil {
			t.Fatal(err)
		}
	}
	o.Registry = r
	o.Secret = golden.manifest.SecretKey.Value
	return o
}

// E05 functionally: the golden identity is stored verbatim, leaves the
// pending list and resolves through the sign-in lookup to the account
// it belonged to in Python (oidc_user, id 8).
func TestOIDCIdentitiesMigrate(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	st, err := startClosed(oidcOptions(t, dir, nil))
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dir, before)
	m := openMigrated(t, dir, golden.manifest.SecretKey.Value, st.Report)
	if e := m.entity(t, "E05"); e.Read != 1 || e.Written != 1 {
		t.Fatalf("report %+v", e)
	}
	for _, p := range m.report.Pending {
		if p.Entity == "E05" {
			t.Fatalf("E05 still pending: %+v", p)
		}
	}
	links := &oidc.Links{DB: m.db}
	userID, err := links.Account(t.Context(), auth.Identity{Issuer: "https://idp.golden.test", Subject: "golden-oidc-subject-1"})
	if err != nil || userID != 8 {
		t.Fatalf("identity resolves to %d: %v", userID, err)
	}
	list, err := links.List(t.Context(), 8)
	want := time.Date(2026, 11, 2, 9, 0, 13, 250000000, time.UTC)
	if err != nil || len(list) != 1 || list[0].ID != 1 || !list[0].CreatedAt.Equal(want) {
		t.Fatalf("list %+v %v", list, err)
	}
	_ = m.db.Close()
	if again, err := startClosed(oidcOptions(t, dir, nil)); err != nil || again.State != S2 {
		t.Fatalf("second start: %+v, %v", again, err)
	}
}

// Rows of deleted accounts stay in the legacy database and are named in
// the report; a duplicate issuer and subject stops the migration (the
// specification's STOP on a uniqueness violation).
func TestOIDCIdentitiesEdgeCases(t *testing.T) {
	t.Parallel()
	t.Run("deleted account", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		execLegacySQL(t, dir, `PRAGMA foreign_keys = OFF; INSERT INTO oidc_identities (id, user_id, issuer, subject, created_at)
			VALUES (2, 9999, 'https://idp.golden.test', 'orphan', '2026-11-02 09:00:14')`)
		st, err := startClosed(oidcOptions(t, dir, nil))
		if err != nil || !st.Migrated {
			t.Fatalf("migration: %+v, %v", st, err)
		}
		m := openMigrated(t, dir, golden.manifest.SecretKey.Value, st.Report)
		if e := m.entity(t, "E05"); e.Read != 2 || e.Written != 1 || len(e.Notes) != 1 {
			t.Fatalf("report %+v", e)
		}
	})
	t.Run("duplicate issuer and subject", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		execLegacySQL(t, dir,
			`ALTER TABLE oidc_identities RENAME TO oidc_identities_old`,
			`CREATE TABLE oidc_identities (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, issuer VARCHAR(512) NOT NULL,
				subject VARCHAR(512) NOT NULL, created_at DATETIME NOT NULL)`,
			`INSERT INTO oidc_identities SELECT * FROM oidc_identities_old`,
			`DROP TABLE oidc_identities_old`,
			`INSERT INTO oidc_identities VALUES (2, 1, 'https://idp.golden.test', 'golden-oidc-subject-1', '2026-11-02 09:00:14')`)
		before := legacySnapshot(t, dir)
		_, err := startClosed(oidcOptions(t, dir, nil))
		var stop *StopError
		if !errors.As(err, &stop) || stop.Entity != "E05" {
			t.Fatalf("want a stop in E05, got %v", err)
		}
		assertUntouched(t, dir, before)
		assertNoGoDatabase(t, dir)
	})
	t.Run("failure in the step", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		before := legacySnapshot(t, dir)
		wrap := func(s Step) Step { return &failingStep{Step: s, target: "E05"} }
		if _, err := startClosed(oidcOptions(t, dir, wrap)); err == nil {
			t.Fatal("injected failure not reported")
		}
		assertUntouched(t, dir, before)
		assertNoGoDatabase(t, dir)
	})
}
