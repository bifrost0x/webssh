package accounts

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// ownedSchema is a store of another owner with per-account rows, and a
// session table shaped like internal/session's, for the sweep.
func ownedSchema() store.Schema {
	return store.Schema{Owner: "hostops", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE hostops_rows (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, v TEXT NOT NULL) STRICT;
CREATE TABLE hostops_global (id INTEGER PRIMARY KEY, v TEXT NOT NULL) STRICT;`}}}
}

func sessionLikeSchema() store.Schema {
	return store.Schema{Owner: "session", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE session_sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL) STRICT;
CREATE TABLE session_revocations (seq INTEGER PRIMARY KEY, session_id TEXT NOT NULL, user_id INTEGER NOT NULL) STRICT;`}}}
}

// fakeSessions deletes from the session-like table and records what it
// published, like internal/session.
type fakeSessions struct {
	mu        sync.Mutex
	published []principal.Revocation
	fail      error
}

func (f *fakeSessions) RevokeUserTx(ctx context.Context, tx *store.Tx, userID int64, reason principal.Reason, except string) ([]principal.Revocation, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	rows, err := tx.QueryContext(ctx, `DELETE FROM session_sessions WHERE user_id = ? AND id <> ? RETURNING id`, userID, except)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []principal.Revocation
	for rows.Next() {
		r := principal.Revocation{UserID: userID, Reason: reason}
		if err := rows.Scan(&r.SessionID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (f *fakeSessions) Publish(revs []principal.Revocation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = append(f.published, revs...)
}

func (f *fakeSessions) list() []principal.Revocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]principal.Revocation(nil), f.published...)
}

type fakeLive struct {
	mu    sync.Mutex
	ended []principal.Revocation
}

func (f *fakeLive) EndAccount(id int64, reason principal.Reason) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ended = append(f.ended, principal.Revocation{UserID: id, Reason: reason})
}

func (f *fakeLive) list() []principal.Revocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]principal.Revocation(nil), f.ended...)
}

type warningAudit struct {
	recordingAudit
	warnings []string
}

func (a *warningAudit) SecurityWarning(event string, _ ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.warnings = append(a.warnings, event)
}

type lifecycle struct {
	s        *Service
	sessions *fakeSessions
	live     *fakeLive
	audit    *warningAudit
}

func newLifecycle(t *testing.T, admins ...string) lifecycle {
	t.Helper()
	l := lifecycle{sessions: &fakeSessions{}, live: &fakeLive{}, audit: &warningAudit{}}
	l.s, _ = newService(t, admins...)
	l.s.DB = storetest.Open(t, Schema(), ownedSchema(), sessionLikeSchema())
	l.s.Audit = l.audit
	l.s.Sessions = l.sessions
	l.s.Live = l.live
	l.s.Data = TableSweep{Keep: DefaultKeep}
	return l
}

func (l lifecycle) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if err := l.s.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), q, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (l lifecycle) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := l.s.DB.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), q, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (l lifecycle) get(t *testing.T, id int64) Account {
	t.Helper()
	a, err := l.s.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLockEndsSessionsAndLiveAccess(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 3, "carol", false, false, ManagedLocal, "x")
	l.exec(t, `INSERT INTO session_sessions (id, user_id) VALUES ('a', 2), ('b', 2), ('c', 1)`)
	admin := principaltest.Admin(1)

	if _, err := l.s.Manage(t.Context(), admin, 1, ActionLock); !errors.Is(err, ErrLockSelf) || message(err) != "You cannot lock your own account" {
		t.Fatalf("self lock: %v", err)
	}
	acc, err := l.s.Manage(t.Context(), admin, 2, ActionLock)
	if err != nil || !acc.IsLocked || acc.AuthGeneration != 1 {
		t.Fatalf("lock: %+v %v", acc, err)
	}
	if got := l.sessions.list(); len(got) != 2 || got[0].Reason != principal.ReasonAccountLocked || got[0].UserID != 2 {
		t.Fatalf("published %+v", got)
	}
	if n := l.count(t, `SELECT count(*) FROM session_sessions WHERE user_id = 2`); n != 0 {
		t.Fatalf("%d sessions left", n)
	}
	if n := l.count(t, `SELECT count(*) FROM session_sessions WHERE user_id = 1`); n != 1 {
		t.Fatal("the administrator's session ended")
	}
	if len(l.live.list()) != 0 {
		t.Fatal("live access ended twice: the published sessions already reach the terminals")
	}
	// An account without a session still gets its live resources ended
	// (terminals of an expired session, detached tmux sessions).
	if _, err := l.s.Manage(t.Context(), admin, 3, ActionLock); err != nil {
		t.Fatal(err)
	}
	if got := l.live.list(); len(got) != 1 || got[0].UserID != 3 || got[0].Reason != principal.ReasonAccountLocked {
		t.Fatalf("live %+v", got)
	}
	if st, _ := l.s.Standing(t.Context(), 2); !st.Locked {
		t.Fatal("standing not locked")
	}
	acc, err = l.s.Manage(t.Context(), admin, 2, ActionUnlock)
	if err != nil || acc.IsLocked || acc.AuthGeneration != 1 {
		t.Fatalf("unlock: %+v %v", acc, err)
	}
	if w := l.audit.warnings; len(w) != 3 || w[0] != "ADMIN_USER_CHANGED" {
		t.Fatalf("audit %v", w)
	}
}

func TestManageRules(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t, "cfg")
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "cfg", true, true, ManagedLocal, "x")
	insertLegacy(t, l.s, 3, "dir", false, false, ManagedLDAP, "x")
	insertLegacy(t, l.s, 4, "gh", false, false, ManagedGitHub, "x")
	insertLegacy(t, l.s, 5, "plain", false, false, ManagedLocal, "x")
	admin := principaltest.Admin(1)
	for _, c := range []struct {
		target int64
		action string
		want   error
	}{
		{9, ActionLock, errNotFound},
		{5, "explode", ErrUnknownAction},
		{3, ActionPromote, ErrPromoteLDAP},
		{4, ActionPromote, ErrPromoteGitHub},
		{1, ActionDemote, ErrDemoteSelf},
		{2, ActionDemote, ErrDemoteManaged}, // locked listed admin stays managed
	} {
		if _, err := l.s.Manage(t.Context(), admin, c.target, c.action); !errors.Is(err, c.want) || message(err) != message(c.want) {
			t.Errorf("%d %s: %v, want %v", c.target, c.action, err, c.want)
		}
	}
	if code(ErrDemoteManaged) != fault.Conflict {
		t.Fatal("ADMIN_USERS demote must be 409")
	}
	if l.get(t, 3).IsAdmin || l.get(t, 4).IsAdmin || !l.get(t, 2).IsAdmin {
		t.Fatal("a refused change was applied")
	}
	acc, err := l.s.Manage(t.Context(), admin, 5, ActionPromote)
	if err != nil || !acc.IsAdmin {
		t.Fatalf("promote: %+v %v", acc, err)
	}
	acc, err = l.s.Manage(t.Context(), admin, 5, ActionDemote)
	if err != nil || acc.IsAdmin {
		t.Fatalf("demote: %+v %v", acc, err)
	}
	// Python keeps a demoted account signed in; it loses the rights at its
	// next request (session.Check compares the recorded rights).
	if len(l.sessions.list()) != 0 || len(l.live.list()) != 0 {
		t.Fatal("promote or demote ended sessions")
	}
}

func TestDemoteLastAdministratorIsRefused(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	// A principal that still carries rights it lost cannot demote the last
	// administrator either; the count is taken inside the transaction.
	if _, err := l.s.Manage(t.Context(), principaltest.Admin(7), 1, ActionDemote); !errors.Is(err, ErrDemoteLast) {
		t.Fatalf("%v", err)
	}
}

// Two administrators demoting each other at the same time leave one.
func TestConcurrentDemotionsKeepAnAdministrator(t *testing.T) {
	t.Parallel()
	for range 20 {
		l := newLifecycle(t)
		insertLegacy(t, l.s, 1, "alice", true, false, ManagedLocal, "x")
		insertLegacy(t, l.s, 2, "bob", true, false, ManagedLocal, "x")
		insertLegacy(t, l.s, 3, "carol", true, false, ManagedLocal, "x")
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for _, pair := range [][2]int64{{1, 2}, {2, 3}, {3, 1}} {
			wg.Go(func() {
				if _, err := l.s.Manage(context.Background(), principaltest.Admin(pair[0]), pair[1], ActionDemote); err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				} else if !errors.Is(err, ErrDemoteLast) {
					t.Errorf("unexpected: %v", err)
				}
			})
		}
		wg.Wait()
		if n := l.count(t, `SELECT count(*) FROM accounts_users WHERE is_admin = 1`); n < 1 || n != 3-ok {
			t.Fatalf("%d administrators after %d demotions", n, ok)
		}
	}
}

// A lock and a concurrent sign-in standing check never see the account
// unlocked with the old generation.
func TestConcurrentLockAndPromote(t *testing.T) {
	t.Parallel()
	l := newLifecycle(t)
	insertLegacy(t, l.s, 1, "admin", true, false, ManagedLocal, "x")
	insertLegacy(t, l.s, 2, "bob", false, false, ManagedLocal, "x")
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			action := ActionPromote
			if i%2 == 0 {
				action = ActionLock
			}
			if _, err := l.s.Manage(context.Background(), principaltest.Admin(1), 2, action); err != nil {
				t.Errorf("%s: %v", action, err)
			}
		})
	}
	wg.Wait()
	a := l.get(t, 2)
	if !a.IsLocked || !a.IsAdmin || a.AuthGeneration != 5 {
		t.Fatalf("%+v", a)
	}
}
