package accounts

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestDeleteRemovesEveryRowOfTheAccount(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	l.s.LegacyDir = func(id int64) (string, bool) { return "users/user_2", id == 2 }
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 3, "carol", false, false, ManagedLocal, "x")
	l.exec(t, `INSERT INTO hostops_rows (user_id, v) VALUES (2, 'passkey'), (2, 'key'), (3, 'other')`)
	l.exec(t, `INSERT INTO hostops_global (v) VALUES ('global')`)
	l.exec(t, `INSERT INTO session_sessions (id, user_id) VALUES ('s2', 2), ('s3', 3)`)
	l.exec(t, `INSERT INTO session_revocations (session_id, user_id) VALUES ('old', 2)`)
	admin := principaltest.Admin(1)

	if err := l.s.Delete(t.Context(), admin, 1); !errors.Is(err, ErrDeleteSelf) || message(err) != "You cannot delete your own account" {
		t.Fatalf("self: %v", err)
	}
	if err := l.s.Delete(t.Context(), admin, 9); code(err) != fault.NotFound {
		t.Fatalf("missing: %v", err)
	}
	if err := l.s.Delete(t.Context(), admin, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.Get(t.Context(), 2); code(err) != fault.NotFound {
		t.Fatalf("account still there: %v", err)
	}
	if n := l.count(t, `SELECT count(*) FROM hostops_rows WHERE user_id = 2`); n != 0 {
		t.Fatalf("%d rows of the deleted account left", n)
	}
	if l.count(t, `SELECT count(*) FROM hostops_rows WHERE user_id = 3`) != 1 || l.count(t, `SELECT count(*) FROM hostops_global`) != 1 {
		t.Fatal("rows of others removed")
	}
	if l.count(t, `SELECT count(*) FROM session_sessions WHERE user_id = 3`) != 1 || l.count(t, `SELECT count(*) FROM session_revocations`) != 1 {
		t.Fatal("kept tables touched")
	}
	if got := l.sessions.list(); len(got) != 1 || got[0].SessionID != "s2" || got[0].Reason != principal.ReasonAccountLocked {
		t.Fatalf("published %+v", got)
	}
	if l.count(t, `SELECT count(*) FROM accounts_quarantine WHERE path = 'users/user_2' AND former_user_id = 2`) != 1 {
		t.Fatal("legacy directory not indexed")
	}
	// The id is never handed out again.
	acc, err := l.s.Create(t.Context(), CreateRequest{Username: "dave", Password: "password1"})
	if err != nil || acc.ID != 4 {
		t.Fatalf("%+v %v", acc, err)
	}
	if w := l.audit.warnings; !slices.Contains(w, "ADMIN_USER_DELETED") {
		t.Fatalf("audit %v", w)
	}
}

func TestDeleteLastAdministrator(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	if err := l.s.Delete(t.Context(), principaltest.Admin(5), 1); !errors.Is(err, ErrDeleteLast) {
		t.Fatalf("%v", err)
	}
	if a := l.get(t, 1); a.IsLocked {
		t.Fatal("refused deletion locked the account")
	}
}

type failingData struct{}

func (failingData) DeleteUserTx(context.Context, *store.Tx, int64) (map[string]int64, error) {
	return nil, errors.New("disk on fire")
}

func TestFailedDeletionLeavesTheAccountLocked(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	l.s.Data = failingData{}
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	l.exec(t, `INSERT INTO session_sessions (id, user_id) VALUES ('s2', 2)`)
	err := l.s.Delete(t.Context(), principaltest.Admin(1), 2)
	if status, _, msg := fault.Status(err); status != 500 || msg != "User deletion failed; the account remains locked" {
		t.Fatalf("%d %q", status, msg)
	}
	a := l.get(t, 2)
	if !a.IsLocked || a.AuthGeneration != 1 {
		t.Fatalf("%+v", a)
	}
	if len(l.sessions.list()) != 1 {
		t.Fatal("sessions not ended before the removal")
	}
	l.s.Data = nil
	if err := l.s.Delete(t.Context(), principaltest.Admin(1), 2); code(err) != fault.Internal {
		t.Fatalf("no data owner must fail closed: %v", err)
	}
}

func TestSweepRefusesUnexpectedTableNames(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	err := l.s.DB.Write(t.Context(), func(tx *store.Tx) error {
		tables, err := OwnedTablesTx(t.Context(), tx)
		if err != nil {
			return err
		}
		if !slices.Equal(tables, []string{"hostops_rows", "session_revocations", "session_sessions"}) {
			t.Errorf("tables %v", tables)
		}
		if _, err := (TableSweep{}).DeleteUserTx(t.Context(), tx, 0); err == nil {
			t.Error("user id 0 accepted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type fakeFactors struct{ reset []int64 }

func (f *fakeFactors) ResetTx(_ context.Context, _ *store.Tx, id int64) error {
	f.reset = append(f.reset, id)
	return nil
}

type fakeRecovery struct{ calls int }

func (f *fakeRecovery) ReplaceTx(_ context.Context, _ *store.Tx, _ int64, count int) ([]string, error) {
	f.calls++
	return slices.Repeat([]string{"AAAA-BBBB-CCCC-DDDD-EEEE"}, count), nil
}

func TestResetMFA(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	factors := &fakeFactors{}
	l.s.Factors = factors
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	l.exec(t, `UPDATE accounts_users SET mfa_required = 1 WHERE id = 2`)
	admin := principaltest.Admin(1)
	for _, confirm := range []string{"", "Bob", "bob ", "\x00"} {
		if err := l.s.ResetMFA(t.Context(), admin, 2, confirm); !errors.Is(err, ErrTargetConfirmation) {
			t.Fatalf("%q: %v", confirm, err)
		}
	}
	if err := l.s.ResetMFA(t.Context(), admin, 9, "x"); code(err) != fault.NotFound {
		t.Fatalf("missing: %v", err)
	}
	if len(factors.reset) != 0 {
		t.Fatal("factors removed before the confirmation")
	}
	if err := l.s.ResetMFA(t.Context(), admin, 2, "bob"); err != nil {
		t.Fatal(err)
	}
	a := l.get(t, 2)
	if a.MFARequired || a.AuthGeneration != 1 || !slices.Equal(factors.reset, []int64{2}) {
		t.Fatalf("%+v %v", a, factors.reset)
	}
	if got := l.live.list(); len(got) != 1 || got[0].Reason != principal.ReasonFactorChanged {
		t.Fatalf("live %+v", got)
	}
	l.s.Factors = nil
	if err := l.s.ResetMFA(t.Context(), admin, 2, "bob"); code(err) != fault.Unavailable {
		t.Fatalf("unwired: %v", err)
	}
}

func TestReplaceRecovery(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	rec := &fakeRecovery{}
	l.s.Recovery = rec
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	admin := principaltest.Admin(1)
	if _, err := l.s.ReplaceRecovery(t.Context(), admin, 2, "BOB"); !errors.Is(err, ErrTargetConfirmation) || rec.calls != 0 {
		t.Fatalf("%v", err)
	}
	codes, err := l.s.ReplaceRecovery(t.Context(), admin, 2, "bob")
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("%v %v", codes, err)
	}
	if a := l.get(t, 2); a.AuthGeneration != 0 || len(l.sessions.list()) != 0 {
		t.Fatal("a recovery reset ends no session")
	}
}

func TestProvisionTx(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t, "listed")
	insertLegacy(t, l.s, 7, "Straße", false, false, ManagedLocal, "x")
	provision := func(name, manager string) (int64, error) {
		var id int64
		err := l.s.DB.Write(t.Context(), func(tx *store.Tx) error {
			var err error
			id, err = l.s.ProvisionTx(t.Context(), tx, name, manager)
			return err
		})
		return id, err
	}
	for _, c := range []struct {
		name, manager string
		want          error
	}{
		{"strasse", "ldap", ErrProvisionTaken},
		{"STRASSE", "github", ErrProvisionTaken},
		{"x", "", errProvisionManager},
		{"x", "oidc", errProvisionManager},
		{"", "ldap", ErrProvisionName},
		{"a\nb", "ldap", ErrProvisionName},
		{"a‎b", "ldap", ErrProvisionName},
		{"bad\xff", "ldap", ErrProvisionName},
	} {
		if _, err := provision(c.name, c.manager); !errors.Is(err, c.want) {
			t.Errorf("%q %q: %v", c.name, c.manager, err)
		}
	}
	id, err := provision("listed", "ldap")
	if err != nil || id != 8 {
		t.Fatalf("%d %v", id, err)
	}
	a := l.get(t, id)
	if a.IsAdmin || a.IsLocked || a.Managed != ManagedLDAP || a.Incarnation == "" {
		t.Fatalf("%+v", a)
	}
	if err := l.s.Normalize(t.Context()); err != nil || l.get(t, id).IsAdmin {
		t.Fatal("ADMIN_USERS promoted a managed account")
	}
	if _, standing, _ := l.s.SignInStanding(t.Context(), "listed"); standing {
		t.Fatal("a managed account signs in with a local password")
	}
	if id, err := provision("Jörg", "github"); err != nil || id != 9 {
		t.Fatalf("unicode name: %d %v", id, err)
	}
}

func TestTableReset(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	l.exec(t, `INSERT INTO hostops_rows (user_id, v) VALUES (2, 'a'), (3, 'b')`)
	err := l.s.DB.Write(t.Context(), func(tx *store.Tx) error {
		if err := (TableReset{Tables: []string{"hostops_rows"}}).ResetTx(t.Context(), tx, 2); err != nil {
			return err
		}
		for _, bad := range [][]string{nil, {"hostops_global"}, {"missing_table"}, {`hostops_rows"; --`}} {
			if err := (TableReset{Tables: bad}).ResetTx(t.Context(), tx, 2); err == nil {
				t.Errorf("%q accepted", bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if l.count(t, `SELECT count(*) FROM hostops_rows WHERE user_id = 2`) != 0 || l.count(t, `SELECT count(*) FROM hostops_rows`) != 1 {
		t.Fatal("reset")
	}
}
