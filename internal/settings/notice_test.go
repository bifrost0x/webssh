package settings

import (
	"slices"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

func grantNotice(t *testing.T, db *store.DB, userID int64) {
	t.Helper()
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		return GrantNotice(t.Context(), tx, userID, NoticeUpgrade)
	}); err != nil {
		t.Fatal(err)
	}
}

func pending(t *testing.T, s *Service, userID int64) []string {
	t.Helper()
	got, err := s.Notices(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A granted notice stays pending until its own account acknowledges it.
// Acknowledging twice, or a notice the account never had, changes
// nothing, and granting again never brings an acknowledged notice back.
func TestNoticesAreAcknowledgedPerAccount(t *testing.T) {
	s, db := newService(t, Environment{})
	s.now = func() time.Time { return time.UnixMicro(1_700_000_000_000_000) }
	grantNotice(t, db, 3)
	grantNotice(t, db, 4)
	upgrade := []string{NoticeUpgrade}
	for _, id := range []int64{3, 4} {
		if got := pending(t, s, id); !slices.Equal(got, upgrade) {
			t.Fatalf("account %d: %v", id, got)
		}
	}
	if got := pending(t, s, 5); got == nil || len(got) != 0 {
		t.Fatalf("account without a notice: %#v", got)
	}

	left, err := s.AcknowledgeNotice(t.Context(), 3, NoticeUpgrade)
	if err != nil || len(left) != 0 {
		t.Fatalf("acknowledge: %v, %v", left, err)
	}
	if got := pending(t, s, 3); len(got) != 0 {
		t.Fatalf("acknowledged notice still pending: %v", got)
	}
	if got := pending(t, s, 4); !slices.Equal(got, upgrade) {
		t.Fatalf("another account's acknowledgement touched account 4: %v", got)
	}
	var at int64
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT acknowledged_us FROM settings_notices WHERE user_id = 3`).Scan(&at)
	}); err != nil || at != 1_700_000_000_000_000 {
		t.Fatalf("acknowledged_us = %d, %v", at, err)
	}

	s.now = func() time.Time { return time.UnixMicro(1_800_000_000_000_000) }
	if left, err := s.AcknowledgeNotice(t.Context(), 3, NoticeUpgrade); err != nil || len(left) != 0 {
		t.Fatalf("second acknowledgement: %v, %v", left, err)
	}
	if left, err := s.AcknowledgeNotice(t.Context(), 5, NoticeUpgrade); err != nil || len(left) != 0 {
		t.Fatalf("acknowledgement without a notice: %v, %v", left, err)
	}
	if got := pending(t, s, 5); len(got) != 0 {
		t.Fatalf("acknowledging created a notice: %v", got)
	}
	grantNotice(t, db, 3)
	if got := pending(t, s, 3); len(got) != 0 {
		t.Fatalf("a second grant reopened the notice: %v", got)
	}
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT acknowledged_us FROM settings_notices WHERE user_id = 3`).Scan(&at)
	}); err != nil || at != 1_700_000_000_000_000 {
		t.Fatalf("the first acknowledgement was overwritten: %d, %v", at, err)
	}

	for _, bad := range []struct {
		id     int64
		notice string
	}{{3, "upgrade-3.5"}, {3, ""}, {0, NoticeUpgrade}, {-1, NoticeUpgrade}} {
		if _, err := s.AcknowledgeNotice(t.Context(), bad.id, bad.notice); !fault.Is(err, fault.InvalidRequest) {
			t.Errorf("acknowledge %d %q: %v", bad.id, bad.notice, err)
		}
		if err := db.Write(t.Context(), func(tx *store.Tx) error {
			return GrantNotice(t.Context(), tx, bad.id, bad.notice)
		}); err == nil {
			t.Errorf("grant %d %q succeeded", bad.id, bad.notice)
		}
	}
}

// VerifyNotice is the migration's check of GrantNotice: the notice must
// exist and be pending.
func TestVerifyNotice(t *testing.T) {
	s, db := newService(t, Environment{})
	verify := func(userID int64, notice string) error {
		return db.Read(t.Context(), func(tx *store.Tx) error {
			return VerifyNotice(t.Context(), tx, userID, notice)
		})
	}
	if err := verify(3, NoticeUpgrade); err == nil {
		t.Fatal("a missing notice verified")
	}
	grantNotice(t, db, 3)
	if err := verify(3, NoticeUpgrade); err != nil {
		t.Fatal(err)
	}
	if err := verify(3, "upgrade-3.5"); err == nil {
		t.Fatal("an unknown notice verified")
	}
	if _, err := s.AcknowledgeNotice(t.Context(), 3, NoticeUpgrade); err != nil {
		t.Fatal(err)
	}
	if err := verify(3, NoticeUpgrade); err == nil {
		t.Fatal("an acknowledged notice verified as pending")
	}
}

// Deleting an account removes its notices with its other settings.
func TestDeleteUserRemovesNotices(t *testing.T) {
	s, db := newService(t, Environment{})
	grantNotice(t, db, 3)
	grantNotice(t, db, 4)
	if err := db.Write(t.Context(), func(tx *store.Tx) error { return DeleteUser(t.Context(), tx, 3) }); err != nil {
		t.Fatal(err)
	}
	if got := pending(t, s, 3); len(got) != 0 {
		t.Fatalf("notices of a deleted account: %v", got)
	}
	if got := pending(t, s, 4); len(got) != 1 {
		t.Fatalf("notices of another account: %v", got)
	}
}

// The routes read and acknowledge only the signed-in account's notices;
// the body cannot name another account.
func TestNoticeRoutes(t *testing.T) {
	h, mux := newHTTP(t)
	grantNotice(t, h.Settings.db, 3)
	grantNotice(t, h.Settings.db, 4)
	alice, bob := principaltest.User(3), principaltest.User(4)
	const ack = "/api/account/notices/acknowledge"

	if r := call(t, mux, &alice, "GET", "/api/account/notices", "", ""); r.status != 200 || r.raw != `{"notices":["upgrade-3.4"]}` {
		t.Fatalf("pending: %d %s", r.status, r.raw)
	}
	for _, body := range []string{
		`{"notice":"upgrade-3.4","user_id":4}`, `{"notice":"upgrade-3.4","username":"bob"}`,
		`{"notice":"upgrade-3.5"}`, `{"notice":1}`, `{"notice":null}`, `{}`, `[]`, `"upgrade-3.4"`,
	} {
		if r := call(t, mux, &alice, "POST", ack, body, "application/json"); r.status != 400 || r.body["error"] != msgInvalidNotice || r.body["code"] != "invalid_request" {
			t.Errorf("%s: %d %s", body, r.status, r.raw)
		}
	}
	if r := call(t, mux, &alice, "POST", ack, `{"notice":"upgrade-3.4"}`, "text/plain"); r.status != 400 {
		t.Errorf("text/plain: %d %s", r.status, r.raw)
	}
	if r := call(t, mux, &alice, "GET", "/api/account/notices", "", ""); r.raw != `{"notices":["upgrade-3.4"]}` {
		t.Fatalf("a refused request changed the notice: %s", r.raw)
	}

	if r := call(t, mux, &alice, "POST", ack, `{"notice":"upgrade-3.4"}`, "application/json"); r.status != 200 || r.raw != `{"notices":[]}` {
		t.Fatalf("acknowledge: %d %s", r.status, r.raw)
	}
	if r := call(t, mux, &alice, "GET", "/api/account/notices", "", ""); r.raw != `{"notices":[]}` {
		t.Fatalf("after the acknowledgement: %s", r.raw)
	}
	if r := call(t, mux, &bob, "GET", "/api/account/notices", "", ""); r.raw != `{"notices":["upgrade-3.4"]}` {
		t.Fatalf("alice's acknowledgement reached bob: %s", r.raw)
	}
	if r := call(t, mux, &alice, "POST", ack, `{"notice":"upgrade-3.4"}`, "application/json"); r.status != 200 || r.raw != `{"notices":[]}` {
		t.Fatalf("second acknowledgement: %d %s", r.status, r.raw)
	}
}
