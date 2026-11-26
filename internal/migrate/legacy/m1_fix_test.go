package legacy

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/store"
)

// M1 of the review: what E28 does not migrate (directories and
// command-set references, contexts of deleted profiles) is pending with
// its number, so the purge guard sees it; the notes are migrated.
func TestM1HostContextPartlyPending(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	var found *Pending
	for i, p := range m.report.Pending {
		if p.Entity == "E28" {
			found = &m.report.Pending[i]
		}
	}
	if found == nil || found.Phase != "B6" || found.Count != 1 {
		t.Fatalf("E28 pending: %+v", found)
	}
	if e := m.entity(t, "E28"); e.Written != 1 {
		t.Fatalf("E28 notes: %+v", e)
	}
	kinds := map[string]bool{}
	for _, c := range m.report.Coverage {
		if c.Entity == "E28" {
			kinds[c.Kind] = true
		}
	}
	if !kinds[CoverStep] || !kinds[CoverPending] {
		t.Fatalf("coverage of E28: %v", kinds)
	}
}

func TestRegistryPartlyPending(t *testing.T) {
	t.Parallel()
	count := func(context.Context, *Source) (int, error) { return 0, nil }
	r := NewRegistry()
	if err := r.PartlyPending("E28", "B5", count); err == nil {
		t.Fatal("partly pending without a step")
	}
	if err := r.Add(GroupHostContext, func() Step { return &hostNotesStep{} }); err != nil {
		t.Fatal(err)
	}
	if err := r.PartlyPending("E28", "", count); err == nil {
		t.Fatal("no phase accepted")
	}
	if err := r.PartlyPending("E28", "B5", count); err != nil {
		t.Fatal(err)
	}
	if err := r.PartlyPending("E28", "B5", count); err == nil {
		t.Fatal("pending twice")
	}
}

// N1, N7: the id floor lies above every id of a deleted account and of a
// user directory without an account, so Go never hands out an id for
// which legacy data exists.
func TestM1IDFloorCoversLegacyIDs(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		path  string
		floor int64
	}{
		"deleted account": {"deleted_users/user_999_0123456789abcdef0123456789abcdef/profiles.json", 999},
		"orphan user dir": {"users/user_500/settings.json", 500},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			writeLegacyFile(t, dir, tc.path, `{"schema_version": 2}`)
			m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
			err := m.db.Read(t.Context(), func(tx *store.Tx) error {
				floor, err := accounts.IDFloorTx(t.Context(), tx)
				if err == nil && floor < tc.floor {
					t.Errorf("id floor %d, want at least %d", floor, tc.floor)
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// N2: a host context of a deleted profile is not imported.
func TestM1OrphanHostContextNotImported(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	orphan := fx.Values.Extended.OrphanHostContext
	if orphan.ProfileID == "" || orphan.Notes == "" {
		t.Fatal("fixture has no orphan host context with notes")
	}
	dir := extractLegacy(t, "datadir-extended.tar")
	m := migrateM1(t, dir, fx.SecretKey.Value, M1{})
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		n := 0
		err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM hostops_notes WHERE profile_id = ?`, orphan.ProfileID).Scan(&n)
		if n != 0 {
			t.Errorf("the orphan context's note was imported")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// N3: a damaged unfinished TOTP enrolment is discarded and counted like
// every enrolment (D-02); it does not stop the migration.
func TestM1DamagedEnrolmentIsDiscarded(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	execLegacySQL(t, dir, `UPDATE totp_enrollments SET encrypted_secret = 'gAAAAAdamaged'`)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	if e := m.entity(t, "E09"); e.Discarded != 1 {
		t.Fatalf("%+v", e)
	}
	if e := m.entity(t, "E08"); e.Written != 1 {
		t.Fatalf("%+v", e)
	}
}

// N4: for an account whose stored host facts Python drops, the
// verification still compares every other field of every profile.
func TestM1HostsVerifiedDespiteDroppedFacts(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	replaceIn(t, filepath.Join(dir, "users", "user_3", "profiles.json"), `"port": 22`, `"port": 22, "detected_family": 12345`)
	m := M1{}
	m.wrap = func(s Step) Step {
		return &tamperStep{Step: s, target: "E19", tamper: execTx(`UPDATE hosts_profiles SET "host" = '"tampered.test"' WHERE user_id = 3 AND position = 0`)}
	}
	_, err := startClosed(m1Options(t, dir, m))
	if se := assertStop(t, err, "E19"); se.Code != CodeVerifyFailed {
		t.Fatalf("%v", se)
	}
	ok := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	if !strings.Contains(strings.Join(ok.entity(t, "E19").Notes, " "), "dropped") {
		t.Fatalf("the dropped fact is not reported: %+v", ok.entity(t, "E19"))
	}
}

// N5: host_context.json "version" is compared like Python's != 1, so
// 1.0 and true are accepted.
func TestHostContextVersionLikePython(t *testing.T) {
	t.Parallel()
	for v, ok := range map[string]bool{"1": true, "1.0": true, "true": true, "1e0": true, "2": false, `"1"`: false, "false": false, "null": false} {
		var s hostNotesStep
		err := s.readContexts(1, []byte(`{"version":`+v+`,"hosts":{}}`), nil)
		if (err == nil) != ok {
			t.Errorf("version %s: %v", v, err)
		}
	}
}

// N6: a STOP for an unusable password hash names the account, never a
// part of the hash.
func TestM1PasswordStopHidesHash(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	const hash = "$9z$12$SECRETPARTabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS"
	execLegacySQL(t, dir, `UPDATE users SET password_hash = '`+hash+`' WHERE id = 4`)
	_, err := startClosed(m1Options(t, dir, M1{}))
	se := assertStop(t, err, "E02")
	text := se.Error() + " " + se.Message
	for _, part := range []string{"9z", "SECRETPART", "'9'", "'z'"} {
		if strings.Contains(text, part) {
			t.Fatalf("STOP shows part of the hash: %s", text)
		}
	}
	if se.UserID != 4 {
		t.Fatalf("user %d", se.UserID)
	}
}

// An id in a directory name above maxDirectoryID is no id Python handed
// out; it neither raises the id floor (which would leave no ids, or
// overflow) nor stops the migration. The directory stays in place and the
// report names it.
func TestM1IDFloorIgnoresImplausibleIDs(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	deleted := "deleted_users/user_9223372036854775807_0123456789abcdef0123456789abcdef"
	orphan := "users/user_2147483648"
	writeLegacyFile(t, dir, deleted+"/profiles.json", `{"schema_version": 2}`)
	writeLegacyFile(t, dir, orphan+"/settings.json", `{"schema_version": 2}`)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		floor, err := accounts.IDFloorTx(t.Context(), tx)
		if err == nil && floor > maxDirectoryID {
			t.Errorf("id floor %d", floor)
		}
		q, err2 := accounts.QuarantineTx(t.Context(), tx)
		if _, ok := q[deleted]; ok {
			t.Errorf("implausible id indexed")
		}
		return errors.Join(err, err2)
	})
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]string{}
	for _, k := range m.report.KeptInPlace {
		kept[k.Path] = k.Reason
	}
	if kept[deleted] != "implausible_account_id" || kept[orphan] != "user_directory_without_account" {
		t.Errorf("kept in place %v", kept)
	}
	notes := strings.Join(append(m.entity(t, "E01").Notes, m.entity(t, "E33").Notes...), "\n")
	for _, p := range []string{deleted, orphan} {
		if !strings.Contains(notes, p) {
			t.Errorf("report does not name %s: %s", p, notes)
		}
	}
}
