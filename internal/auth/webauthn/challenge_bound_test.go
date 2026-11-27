package webauthn

import (
	"strconv"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// A flood of anonymous sign-in options must not push out the challenge
// of an account's ceremony, and one account cannot hold more than
// maxPerAccount challenges (RS2-07).
func TestAnonymousChallengesKeepAccountChallenges(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	c := e.svc.challenges()
	ctx := t.Context()
	if _, err := c.issue(ctx, purposeStepUp, 1, "victim-binding-0001"); err != nil {
		t.Fatal(err)
	}
	now := e.clock.Now()
	err := e.svc.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
			INSERT INTO webauthn_challenges (purpose, binding_hash, user_id, sealed_challenge, created_at, expires_at)
			SELECT 'login', randomblob(32), NULL, x'00', ?, ? FROM n`, maxChallenges, now.UnixMicro(), now.Add(ChallengeTTL).UnixMicro())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := c.issue(ctx, purposeLogin, 0, "flood-binding-00-"+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.consume(ctx, purposeStepUp, 1, "victim-binding-0001"); err != nil {
		t.Fatalf("account challenge evicted by anonymous options: %v", err)
	}
	for i := range maxPerAccount + 4 {
		if _, err := c.issue(ctx, purposeMFA, 2, "account-binding-"+strconv.Itoa(1000+i)); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	_ = e.svc.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_challenges WHERE user_id = 2`).Scan(&n)
	})
	if n != maxPerAccount {
		t.Fatalf("account holds %d challenges, want %d", n, maxPerAccount)
	}
	if _, err := c.consume(ctx, purposeMFA, 2, "account-binding-"+strconv.Itoa(1000+maxPerAccount+3)); err != nil {
		t.Fatalf("newest account challenge evicted: %v", err)
	}
}
