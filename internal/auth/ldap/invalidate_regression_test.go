package ldap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

type failingRaise struct{ *fakeAccounts }

func (failingRaise) RaiseGenerationTx(context.Context, *store.Tx, int64) error {
	return errors.New("database is locked")
}

// The sweep ends the live sessions even when persisting the
// invalidation fails, as revoke_user_access did (RS2-04).
func TestSweepEndsSessionsWhenGenerationRaiseFails(t *testing.T) {
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	delete(f.dir.entries, "alice") // removed from the directory
	f.now = f.now.Add(time.Hour)
	f.svc.Accounts = failingRaise{f.accounts}
	n, err := f.svc.Sweep(t.Context())
	t.Logf("sweep ended=%d err=%v revocations=%d", n, err, f.sessions.count(7))
	if f.sessions.count(7) == 0 {
		t.Fatal("live sessions of an account refused by the directory were not ended")
	}
}
