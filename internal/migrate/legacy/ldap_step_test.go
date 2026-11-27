package legacy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth/ldap"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

// The golden identity: user 10 (ldap_user) of the default provider.
const (
	goldenLDAPUser    = int64(10)
	goldenLDAPSubject = "b64:Z29sZGVuLWxkYXAtZW50cnktdXVpZA"
)

func ldapM1Registry(t *testing.T, m M1) *Registry {
	t.Helper()
	r := m1Registry(t, m)
	if err := AddLDAP(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func migrateWithLDAP(t *testing.T, dataDir, secret string) migrated {
	t.Helper()
	before := legacySnapshot(t, dataDir)
	o := testOptions(t, dataDir)
	o.Registry = ldapM1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
	o.Secret = secret
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dataDir, before)
	return openMigrated(t, dataDir, secret, st.Report)
}

func TestAddLDAPTakesOverThePendingEntities(t *testing.T) {
	t.Parallel()
	r := ldapM1Registry(t, M1{})
	for _, c := range r.coverage() {
		if (c.Entity == "E03" || c.Entity == "E37") && c.Kind != CoverStep {
			t.Errorf("%s is %s", c.Entity, c.Kind)
		}
	}
	if len(r.Uncovered()) != 0 {
		t.Fatalf("uncovered %v", r.Uncovered())
	}
	if err := AddLDAP(r); err == nil {
		t.Fatal("registering the steps twice must fail")
	}
}

// migratedDirectory is a directory that knows ldap_user with the golden
// subject.
type migratedDirectory struct{ subject string }

func (d migratedDirectory) Lookup(_ context.Context, name string) (ldap.Entry, error) {
	if name != "ldap_user" {
		return ldap.Entry{}, ldap.ErrRejected
	}
	return ldap.Entry{Subject: d.subject, DN: "uid=ldap_user,ou=people,dc=golden,dc=test"}, nil
}

func (migratedDirectory) VerifyPassword(_ context.Context, _, pw string) (bool, error) {
	return pw == "directory-pw", nil
}
func (migratedDirectory) Probe(context.Context) error { return nil }
func (migratedDirectory) Ready() error                { return nil }
func (migratedDirectory) Transport() string           { return "ldaps" }

// migratedAccounts adapts the migrated account store to ldap.Accounts.
type migratedAccounts struct{ a *accounts.Service }

func (m migratedAccounts) GetTx(ctx context.Context, tx *store.Tx, id int64) (ldap.Account, error) {
	acc, err := accounts.GetTx(ctx, tx, id)
	return ldap.Account{ID: acc.ID, Username: acc.Username, IsAdmin: acc.IsAdmin, IsLocked: acc.IsLocked,
		Generation: acc.AuthGeneration, Managed: string(acc.Managed)}, err
}
func (m migratedAccounts) ProvisionTx(ctx context.Context, tx *store.Tx, name, manager string) (int64, error) {
	return m.a.ProvisionTx(ctx, tx, name, manager)
}
func (migratedAccounts) ReleaseTx(context.Context, *store.Tx, int64, string) error { return nil }
func (migratedAccounts) AdoptTx(context.Context, *store.Tx, int64, string) error   { return nil }
func (m migratedAccounts) RaiseGenerationTx(ctx context.Context, tx *store.Tx, id int64) error {
	_, err := m.a.RaiseGenerationTx(ctx, tx, id)
	return err
}
func (m migratedAccounts) BreakGlassAdminTx(ctx context.Context, tx *store.Tx) (bool, error) {
	return m.a.BreakGlassAdminTx(ctx, tx)
}

type countingSessions struct{ n int }

func (c *countingSessions) RevokeAccountTx(_ context.Context, _ *store.Tx, userID int64, reason principal.Reason) ([]principal.Revocation, error) {
	return []principal.Revocation{{UserID: userID, Reason: reason}}, nil
}

func (c *countingSessions) Publish(revs []principal.Revocation) { c.n += len(revs) }

func ldapServiceOn(m migrated, provider, subject string) (*ldap.Service, *countingSessions) {
	sessions := &countingSessions{}
	return &ldap.Service{DB: m.db, Directory: migratedDirectory{subject: subject}, Accounts: migratedAccounts{&accounts.Service{DB: m.db}},
		Sessions: sessions, Enabled: true, Provider: provider, Revalidation: 5 * time.Minute}, sessions
}

// TestLDAPIdentityMigratesFunctionally is E03: the identity is copied
// verbatim, and a directory sign-in with the stored binding resolves to
// the same account.
func TestLDAPIdentityMigratesFunctionally(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateWithLDAP(t, dir, golden.manifest.SecretKey.Value)
	if e := m.entity(t, "E03"); e.Read != 1 || e.Written != 1 {
		t.Fatalf("E03 report %+v", e)
	}
	var rows []ldap.Identity
	if err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		rows, err = ldap.IdentitiesTx(t.Context(), tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 11, 2, 9, 0, 10, 250000000, time.UTC)
	if len(rows) != 1 || rows[0].ID != 1 || rows[0].UserID != goldenLDAPUser || rows[0].Provider != "default" ||
		rows[0].Subject != goldenLDAPSubject || rows[0].DirectoryUsername != "ldap_user" ||
		rows[0].DistinguishedName != "uid=ldap_user,ou=people,dc=golden,dc=test" || !rows[0].CreatedAt.Equal(want) || !rows[0].LastVerifiedAt.Equal(want) {
		t.Fatalf("rows %+v", rows)
	}
	svc, _ := ldapServiceOn(m, "default", goldenLDAPSubject)
	if id, err := svc.Authenticate(t.Context(), "ldap_user", "directory-pw"); err != nil || id != goldenLDAPUser {
		t.Fatalf("sign-in with the migrated binding: %d %v", id, err)
	}
	if _, err := svc.Authenticate(t.Context(), "ldap_user", "wrong"); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	// A directory that now reports another subject does not reach the
	// account (the binding, not the name, decides).
	other, _ := ldapServiceOn(m, "default", "b64:other")
	if _, err := other.Authenticate(t.Context(), "ldap_user", "directory-pw"); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("other subject: %v", err)
	}
	// The local password of the managed account does not sign in.
	if id, err := testProvider(t, m.db).Authenticate(t.Context(), "ldap_user", "irrelevant"); err == nil {
		t.Fatalf("local sign-in of an LDAP account: %d", id)
	}
}

func TestLDAPIdentityOfMissingAccountIsFlagged(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	execLegacySQL(t, dir, `PRAGMA foreign_keys = OFF`, `INSERT INTO ldap_identities (id, user_id, provider, subject, directory_username, distinguished_name, created_at)
		VALUES (2, 999, 'default', 'orphan', 'ghost', 'uid=ghost', '2026-11-02 09:00:00')`)
	m := migrateWithLDAP(t, dir, golden.manifest.SecretKey.Value)
	e := m.entity(t, "E03")
	if e.Written != 1 || !hasFlag(e.Flagged, 999, "LDAP identity of a missing account") {
		t.Fatalf("E03 report %+v", e)
	}
}

// TestLDAPFenceMigratesFunctionally is E37 on the extended data set: the
// fenced account has its generation raised, is signed out by the gate,
// and its next directory sign-in checks the directory and clears the
// fence. The fence file stays.
func TestLDAPFenceMigratesFunctionally(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	dir := extractLegacy(t, "datadir-extended.tar")
	src := openLegacy(t, dir)
	rows, err := src.AccountRows(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	legacyGen := int64(-1)
	for _, r := range rows {
		if r.ID == goldenLDAPUser {
			legacyGen = r.AuthGeneration
		}
	}
	src.Close()
	m := migrateWithLDAP(t, dir, fx.SecretKey.Value)
	e := m.entity(t, "E37")
	if e.Written != 1 || !hasFlag(e.Flagged, goldenLDAPUser, "LDAP revocation fence") || len(e.KeptInPlace) != 1 {
		t.Fatalf("E37 report %+v", e)
	}
	acc, err := (&accounts.Service{DB: m.db}).Get(t.Context(), goldenLDAPUser)
	if err != nil || acc.AuthGeneration != legacyGen+1 {
		t.Fatalf("generation %d, legacy %d (%v)", acc.AuthGeneration, legacyGen, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, ldapFencesDir, "10")); err != nil {
		t.Fatalf("fence file: %v", err)
	}
	svc, sessions := ldapServiceOn(m, "default", goldenLDAPSubject)
	if err := svc.Gate(t.Context(), principaltest.User(goldenLDAPUser)); !fault.Is(err, fault.AuthenticationNeeded) {
		t.Fatalf("gate before the check: %v", err)
	}
	if _, err := svc.Authenticate(t.Context(), "ldap_user", "directory-pw"); err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if sessions.n != 2 {
		t.Fatalf("sessions ended %d times, want the gate and the sign-in", sessions.n)
	}
	if err := svc.Gate(t.Context(), principaltest.User(goldenLDAPUser)); err != nil {
		t.Fatalf("gate after the check: %v", err)
	}
}

func TestLDAPFenceNamesThatPythonIgnores(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	for _, name := range []string{"010", "abc", "999", "-1"} {
		writeLegacyFile(t, dir, filepath.Join(ldapFencesDir, name), "pending\n")
	}
	writeLegacyFile(t, dir, filepath.Join(ldapFencesDir, fmt.Sprint(goldenLDAPUser)), "pending\n")
	m := migrateWithLDAP(t, dir, golden.manifest.SecretKey.Value)
	e := m.entity(t, "E37")
	if e.Written != 1 || e.Read != 5 || len(e.Notes) != 1 {
		t.Fatalf("E37 report %+v", e)
	}
}

func TestLDAPFenceDirectoryUnreadableFencesEveryLDAPAccount(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions without root")
	}
	dir := copyGolden(t)
	fences := filepath.Join(dir, ldapFencesDir)
	if err := os.Mkdir(fences, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fences, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fences, 0o700) })
	o := testOptions(t, dir)
	o.Registry = ldapM1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	m := openMigrated(t, dir, golden.manifest.SecretKey.Value, st.Report)
	e := m.entity(t, "E37")
	if e.Written != 1 || len(e.Warnings) != 1 || e.Warnings[0].Code != "ldap_fences_unreadable" {
		t.Fatalf("E37 report %+v", e)
	}
}
