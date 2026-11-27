package ldap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// ctxDirectory behaves like Client.Lookup: a cancelled request context
// surfaces as ErrUnavailable.
type ctxDirectory struct {
	*fakeDirectory
	cancel context.CancelFunc
}

func (d ctxDirectory) Lookup(ctx context.Context, name string) (Entry, error) {
	d.cancel() // the browser aborts the request while the directory is asked
	<-ctx.Done()
	return Entry{}, fmt.Errorf("%w: search: %w", ErrUnavailable, ctx.Err())
}

// A client abort during the revalidation is no directory refusal: the
// account keeps its access and the next request checks again.
func TestGateClientAbortKeepsAccess(t *testing.T) {
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	f.now = f.now.Add(time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	f.svc.Directory = ctxDirectory{f.dir, cancel}
	gen := f.accounts.get(7).Generation
	err := f.svc.Gate(ctx, principaltest.User(7))
	if err == nil {
		t.Fatal("an aborted revalidation passed the gate")
	}
	if f.accounts.get(7).Generation != gen || f.sessions.count(7) != 0 {
		t.Fatal("a client abort during revalidation ended every session of the account")
	}
}

// refusingDirectory answers with a different stable identity and the
// client aborts right after the answer.
type refusingDirectory struct {
	*fakeDirectory
	cancel context.CancelFunc
}

func (d refusingDirectory) Lookup(ctx context.Context, name string) (Entry, error) {
	e, err := d.fakeDirectory.Lookup(ctx, name)
	e.Subject = "uuid-other"
	d.cancel()
	return e, err
}

// A refusal found before the client aborted still persists (RS2-11).
func TestGateRefusalPersistsAfterClientAbort(t *testing.T) {
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	f.now = f.now.Add(time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	f.svc.Directory = refusingDirectory{f.dir, cancel}
	gen := f.accounts.get(7).Generation
	_ = f.svc.Gate(ctx, principaltest.User(7))
	if f.accounts.get(7).Generation == gen || f.sessions.count(7) == 0 {
		t.Fatal("the refusal of the directory was not persisted after the client aborted")
	}
}
