package settings

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

func TestRecoveryNoticeAfterRestore(t *testing.T) {
	t.Parallel()
	s, db := newService(t, Environment{})
	if at, needs, err := s.RecoveryCheck(t.Context(), 3); err != nil || at != "" || needs {
		t.Fatalf("before a restore: %q %v %v", at, needs, err)
	}
	first := time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)
	mark := func(at time.Time) {
		if err := db.Write(t.Context(), func(tx *store.Tx) error { return MarkRestoredTx(t.Context(), tx, at) }); err != nil {
			t.Fatal(err)
		}
	}
	mark(first)
	at, needs, err := s.RecoveryCheck(t.Context(), 3)
	if err != nil || at != "2026-11-14T06:00:00+00:00" || !needs {
		t.Fatalf("after a restore: %q %v %v", at, needs, err)
	}
	if ok, err := s.ReviewRecovery(t.Context(), 3, "2026-11-14T05:00:00+00:00"); err != nil || ok {
		t.Fatalf("an old checklist dismissed the notice: %v %v", ok, err)
	}
	if ok, err := s.ReviewRecovery(t.Context(), 3, at); err != nil || !ok {
		t.Fatalf("review: %v %v", ok, err)
	}
	if _, needs, _ := s.RecoveryCheck(t.Context(), 3); needs {
		t.Fatal("still needs review")
	}
	if _, needs, _ := s.RecoveryCheck(t.Context(), 4); !needs {
		t.Fatal("the review of one account dismissed it for another")
	}
	mark(first.Add(time.Minute + 1500*time.Microsecond))
	if at, needs, _ := s.RecoveryCheck(t.Context(), 3); !needs || at != "2026-11-14T06:01:00.001500+00:00" {
		t.Fatalf("a new restore needs a fresh review: %q %v", at, needs)
	}
}

func TestValidRecoveryTime(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"2026-11-14T06:00:00+00:00": true, "2026-11-14T06:00:00.123456+02:00": true, "2026-11-14T06:00:00Z": true,
		"2026-11-14T06:00:00": false, "": false, "yesterday": false,
	} {
		if got := ValidRecoveryTime(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}
