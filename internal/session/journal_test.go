package session

import (
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Two services on one database stand for the server and an administrator
// command in another process: the server learns of the command's
// revocations through the journal, and never republishes its own.
func TestFollowRevocationsOfAnotherProcess(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	db := f.svc.db
	other := New(db, testRing(t), f.accounts, nil)
	server := f.svc

	var mu sync.Mutex
	var got []principal.Revocation
	server.Subscribe(func(r principal.Revocation) { mu.Lock(); got = append(got, r); mu.Unlock() })
	snapshot := func() []principal.Revocation {
		mu.Lock()
		defer mu.Unlock()
		return append([]principal.Revocation(nil), got...)
	}

	if n, err := server.FollowRevocations(t.Context()); err != nil || n != 0 {
		t.Fatalf("first call publishes nothing: %d %v", n, err)
	}
	a, _ := f.issue(t, 2, false)
	b, _ := f.issue(t, 2, false)
	own, _ := f.issue(t, 1, false)
	if err := server.Revoke(t.Context(), own.ID, principal.ReasonLogout); err != nil {
		t.Fatal(err)
	}
	before := len(snapshot())
	if n, err := other.RevokeUser(t.Context(), 2, principal.ReasonPasswordChanged, ""); err != nil || n != 2 {
		t.Fatalf("revoke in the other process: %d %v", n, err)
	}
	n, err := server.FollowRevocations(t.Context())
	if err != nil || n != 2 {
		t.Fatalf("followed %d, %v", n, err)
	}
	revs := snapshot()[before:]
	if len(revs) != 2 || revs[0].Reason != principal.ReasonPasswordChanged || revs[0].UserID != 2 {
		t.Fatalf("published %+v", revs)
	}
	ids := map[string]bool{revs[0].SessionID: true, revs[1].SessionID: true}
	if !ids[a.ID] || !ids[b.ID] {
		t.Fatalf("published %+v, want %s and %s", revs, a.ID, b.ID)
	}
	if n, _ := server.FollowRevocations(t.Context()); n != 0 {
		t.Fatalf("published again: %d", n)
	}
}

// Pruning keeps the newest entry, so the sequence never goes back and a
// follower cannot miss the next revocation.
func TestJournalSequenceKeepsIncreasing(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	s, _ := f.issue(t, 2, false)
	if err := f.svc.Revoke(t.Context(), s.ID, principal.ReasonLogout); err != nil {
		t.Fatal(err)
	}
	var first int64
	_ = f.svc.db.Write(t.Context(), func(tx *store.Tx) error {
		if err := tx.QueryRowContext(t.Context(), `SELECT max(seq) FROM session_revocations`).Scan(&first); err != nil {
			return err
		}
		// Age every entry beyond the retention.
		_, err := tx.ExecContext(t.Context(), `UPDATE session_revocations SET at_us = 0`)
		return err
	})
	s2, _ := f.issue(t, 2, false)
	if err := f.svc.Revoke(t.Context(), s2.ID, principal.ReasonLogout); err != nil {
		t.Fatal(err)
	}
	var count, last int64
	_ = f.svc.db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT count(*), max(seq) FROM session_revocations`).Scan(&count, &last)
	})
	if last <= first || count != 1 {
		t.Fatalf("seq %d after %d, %d entries kept", last, first, count)
	}
}
