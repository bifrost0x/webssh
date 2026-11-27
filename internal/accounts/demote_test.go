package accounts

import (
	"context"
	"errors"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

type fakeRoles struct {
	inTx    []int64
	demoted []int64
	fail    error
}

func (f *fakeRoles) DemotedTx(_ context.Context, _ *store.Tx, userID int64) error {
	f.inTx = append(f.inTx, userID)
	return f.fail
}

func (f *fakeRoles) Demoted(userID int64) { f.demoted = append(f.demoted, userID) }

// RS8-R01: a demotion withdraws the administrator grants inside its
// transaction and reconnects the realtime connections after the commit.
// It ends no session: the account keeps its ordinary rights and its
// terminals.
func TestDemoteWithdrawsAdministratorRights(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	roles := &fakeRoles{}
	l.s.Roles = roles
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", true, false, ManagedLocal, "x")
	l.exec(t, `INSERT INTO session_sessions (id, user_id) VALUES ('b', 2)`)
	admin := principaltest.Admin(1)

	acc, err := l.s.Manage(t.Context(), admin, 2, ActionDemote)
	if err != nil || acc.IsAdmin || acc.AuthGeneration != 0 {
		t.Fatalf("demote: %+v %v", acc, err)
	}
	if len(roles.inTx) != 1 || roles.inTx[0] != 2 || len(roles.demoted) != 1 || roles.demoted[0] != 2 {
		t.Fatalf("roles: in tx %v, after commit %v", roles.inTx, roles.demoted)
	}
	if got := l.sessions.list(); len(got) != 0 {
		t.Fatalf("a demotion ended sessions: %+v", got)
	}
	if n := l.count(t, `SELECT count(*) FROM session_sessions WHERE user_id = 2`); n != 1 {
		t.Fatal("the demoted account's session ended")
	}
	if st, _ := l.s.Standing(t.Context(), 2); st.IsAdmin || st.Locked || !st.Exists {
		t.Fatalf("standing %+v", st)
	}
	// A promotion and the other actions withdraw nothing.
	if _, err := l.s.Manage(t.Context(), admin, 2, ActionPromote); err != nil {
		t.Fatal(err)
	}
	if len(roles.inTx) != 1 || len(roles.demoted) != 1 {
		t.Fatalf("a promotion called the role changes: %v %v", roles.inTx, roles.demoted)
	}
}

// A failure to withdraw the grants rolls the demotion back.
func TestDemoteFailsClosed(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	boom := errors.New("grants not dropped")
	roles := &fakeRoles{fail: boom}
	l.s.Roles = roles
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", true, false, ManagedLocal, "x")
	if _, err := l.s.Manage(t.Context(), principaltest.Admin(1), 2, ActionDemote); err == nil {
		t.Fatal("the demotion succeeded although its grants stayed")
	}
	if !l.get(t, 2).IsAdmin || len(roles.demoted) != 0 {
		t.Fatalf("demotion committed or announced: %v", roles.demoted)
	}
}
