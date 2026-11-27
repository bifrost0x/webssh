package files_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
	"github.com/bifrost0x/webssh/internal/principal"
)

var (
	alice  = principal.Principal{UserID: 1, SessionID: "sa", Username: "alice"}
	alice2 = principal.Principal{UserID: 1, SessionID: "sa2", Username: "alice"}
	bob    = principal.Principal{UserID: 2, SessionID: "sb", Username: "bob"}
)

type auditRec struct {
	mu     sync.Mutex
	events [][]any
}

func (a *auditRec) Security(event string, kv ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, append([]any{event}, kv...))
}

func (a *auditRec) last() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return nil
	}
	e := a.events[len(a.events)-1]
	m := map[string]any{"event": e[0]}
	for i := 1; i+1 < len(e); i += 2 {
		m[e[i].(string)] = e[i+1]
	}
	return m
}

type quotas struct {
	mu   sync.Mutex
	used map[int64]int
	max  int
}

func (q *quotas) Reserve(_ context.Context, kind string, user int64, n int64) (func(), error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if kind != "quick_connection" || n != 1 {
		return nil, errors.New("unexpected quota")
	}
	if q.used[user] >= q.max {
		return nil, fault.New(fault.Busy, "")
	}
	q.used[user]++
	return func() { q.mu.Lock(); q.used[user]--; q.mu.Unlock() }, nil
}

func (q *quotas) count(user int64) int { q.mu.Lock(); defer q.mu.Unlock(); return q.used[user] }

type fixture struct {
	svc   *files.Service
	reg   *files.Registry
	b     *filestest.Backend
	id    string
	audit *auditRec
	q     *quotas
	now   *time.Time
}

func newFixture(t *testing.T, o files.Options) *fixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	q := &quotas{used: map[int64]int{}, max: 3}
	f := &fixture{audit: &auditRec{}, q: q, now: &now}
	f.reg = files.NewRegistry(files.RegistryOptions{Quotas: q, Now: clock})
	o.Registry, o.Audit, o.Now = f.reg, f.audit, clock
	f.svc = files.New(o)
	f.b = filestest.New()
	id, err := f.reg.Add(alice, files.SourceSFTPQuick, files.Descriptor{Kind: files.KindSFTP, Label: "a@h", Endpoint: "h:22", Protocol: "SFTP", Ephemeral: true}, f.b)
	if err != nil {
		t.Fatal(err)
	}
	f.id = id
	return f
}

func caller(p principal.Principal) files.Caller { return files.Caller{P: p, Peer: 7} }

func wantCode(t *testing.T, err error, code fault.Code) {
	t.Helper()
	if !fault.Is(err, code) {
		t.Fatalf("err = %v, want %s", err, code)
	}
}

func TestSourceOwnership(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	ctx := context.Background()
	if _, err := f.svc.Home(ctx, caller(alice), f.id); err != nil {
		t.Fatal(err)
	}
	// Another user, another browser session of the same user, a malformed
	// or unknown id: all look the same.
	for _, c := range []struct {
		p  principal.Principal
		id string
	}{{bob, f.id}, {alice2, f.id}, {alice, "sftp-quick:nope"}, {alice, "x"}, {alice, "smb-quick:" + strings.Repeat("a", 200)}} {
		_, err := f.svc.Home(ctx, caller(c.p), c.id)
		wantCode(t, err, fault.SourceUnavailable)
	}
	// A capability the source lacks.
	f.b.SetCapabilities(files.Capabilities{Ops: files.CapList | files.CapRead})
	wantCode(t, f.svc.Delete(ctx, caller(alice), f.id, "/x"), fault.SourceUnavailable)
}

func TestRevokeClosesSourcesAtOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	ctx := context.Background()
	b, release, err := f.reg.Resolve(ctx, alice, f.id, files.CapRead)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	other := filestest.New()
	otherID, err := f.reg.Add(alice2, files.SourceSFTPQuick, files.Descriptor{Kind: files.KindSFTP}, other)
	if err != nil {
		t.Fatal(err)
	}
	f.reg.Revoke(principal.Revocation{SessionID: alice.SessionID, UserID: 1, Reason: principal.ReasonLogout})
	// The held backend is closed too; operations on it fail.
	if _, err := b.Home(ctx); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("held source still open: %v", err)
	}
	if _, err := f.svc.Home(ctx, caller(alice), f.id); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("revoked source resolves: %v", err)
	}
	if _, err := f.svc.Home(ctx, caller(alice2), otherID); err != nil {
		t.Fatalf("other session's source closed: %v", err)
	}
	if f.q.used[1] != 1 {
		t.Fatalf("quota not released: %d", f.q.used[1])
	}
}

func TestCloseDeferredWhileHeld(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	ctx := context.Background()
	b, release, err := f.reg.Resolve(ctx, alice, f.id, files.CapRead)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CloseSource(caller(alice), f.id); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Home(ctx); err != nil {
		t.Fatalf("held source closed early: %v", err)
	}
	if _, _, err := f.reg.Resolve(ctx, alice, f.id, files.CapRead); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("closing source resolves: %v", err)
	}
	release()
	release() // idempotent
	if _, err := b.Home(ctx); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("source open after the hold: %v", err)
	}
	wantCode(t, f.svc.CloseSource(caller(alice), f.id), fault.SourceUnavailable)
	wantCode(t, f.svc.CloseSource(caller(bob), f.id), fault.SourceUnavailable)
}

func TestQuickSourcesQuotaAndLastConnection(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	for range 2 {
		if _, err := f.reg.Add(alice, files.SourceSMBQuick, files.Descriptor{Kind: files.KindSMB}, filestest.New()); err != nil {
			t.Fatal(err)
		}
	}
	extra := filestest.New()
	if _, err := f.reg.Add(alice, files.SourceSFTPQuick, files.Descriptor{Kind: files.KindSFTP}, extra); err == nil {
		t.Fatal("quota not applied")
	}
	if _, err := extra.Home(context.Background()); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatal("refused backend left open")
	}
	f.reg.PeerOpened(1, 7)
	f.reg.PeerOpened(1, 8)
	f.reg.PeerClosed(1, 7)
	if f.q.used[1] != 3 {
		t.Fatalf("sources closed while a connection remains: %d", f.q.used[1])
	}
	f.reg.PeerClosed(1, 8)
	if f.q.used[1] != 0 {
		t.Fatalf("quick sources stay after the last connection: %d", f.q.used[1])
	}
}

func TestSMBIdleSweep(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	smb := filestest.New()
	id, err := f.reg.Add(alice, files.SourceSMBQuick, files.Descriptor{Kind: files.KindSMB, Endpoint: "srv/share"}, smb)
	if err != nil {
		t.Fatal(err)
	}
	*f.now = f.now.Add(299 * time.Second)
	f.reg.Sweep()
	if _, err := f.svc.Home(context.Background(), caller(alice), id); err != nil {
		t.Fatal(err)
	}
	*f.now = f.now.Add(301 * time.Second)
	f.reg.Sweep()
	if _, err := f.svc.Home(context.Background(), caller(alice), id); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("idle SMB source stays: %v", err)
	}
	if _, err := f.svc.Home(context.Background(), caller(alice), f.id); err != nil {
		t.Fatalf("SFTP source swept: %v", err)
	}
}

func TestOpenerOnFirstUse(t *testing.T) {
	t.Parallel()
	reg := files.NewRegistry(files.RegistryOptions{})
	var mu sync.Mutex
	opened := 0
	reg.RegisterKind(files.SourceSFTPSession, func(_ context.Context, p principal.Principal, handle string) (files.Descriptor, files.Backend, error) {
		mu.Lock()
		defer mu.Unlock()
		opened++
		if handle != "term1" || p.UserID != 1 {
			return files.Descriptor{}, nil, errors.New("not yours")
		}
		time.Sleep(10 * time.Millisecond)
		return files.Descriptor{Kind: files.KindSFTP}, filestest.New(), nil
	})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			_, release, err := reg.Resolve(context.Background(), alice, "sftp-session:term1", files.CapList)
			if err != nil {
				t.Error(err)
				return
			}
			release()
		})
	}
	wg.Wait()
	if opened != 1 {
		t.Fatalf("opened %d times", opened)
	}
	if _, _, err := reg.Resolve(context.Background(), bob, "sftp-session:term2", files.CapList); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("opener error: %v", err)
	}
	// A terminal session source is not closed by the user.
	wantCode(t, reg.Close(alice, "sftp-session:term1"), fault.SourceUnavailable)
	reg.LastConnectionClosed(1)
	if _, release, err := reg.Resolve(context.Background(), alice, "sftp-session:term1", files.CapList); err != nil {
		t.Fatalf("terminal source closed with the last connection: %v", err)
	} else {
		release()
	}
}

// The quota is taken before a quick source connects (Reserve), passes to
// the source with Slot.Add and is freed by Release or by the source's end.
func TestReserveBeforeOpen(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{}) // one quick source of alice is open
	ctx := context.Background()
	unused, err := f.reg.Reserve(ctx, alice, files.SourceSMBQuick)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.reg.Reserve(ctx, alice, files.SourceSFTPQuick)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.reg.Reserve(ctx, alice, files.SourceSMBQuick); err == nil {
		t.Fatal("quota not applied before the connection")
	}
	if _, err := f.reg.Reserve(ctx, alice, files.SourceSFTPSession); err != nil {
		t.Fatalf("terminal session sources take no quota: %v", err)
	}
	unused.Release()
	unused.Release() // idempotent
	if f.q.used[1] != 2 {
		t.Fatalf("released slot still counted: %d", f.q.used[1])
	}
	id, err := held.Add(files.Descriptor{Kind: files.KindSFTP}, filestest.New())
	if err != nil {
		t.Fatal(err)
	}
	held.Release() // used by Add: no effect
	if f.q.used[1] != 2 {
		t.Fatalf("release after Add freed the source's quota: %d", f.q.used[1])
	}
	reused := filestest.New()
	if _, err := held.Add(files.Descriptor{Kind: files.KindSFTP}, reused); err == nil {
		t.Fatal("slot used twice")
	}
	if _, err := reused.Home(ctx); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatal("refused backend left open")
	}
	if err := f.reg.Close(alice, id); err != nil {
		t.Fatal(err)
	}
	if f.q.used[1] != 1 {
		t.Fatalf("closed source keeps its quota: %d", f.q.used[1])
	}
}

// endingBackend ends by itself, as an SFTP source whose SSH connection
// went away.
type endingBackend struct {
	*filestest.Backend
	done chan struct{}
}

func (e endingBackend) Done() <-chan struct{} { return e.done }

func TestSourceThatEndsFreesItsQuota(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	b := endingBackend{filestest.New(), make(chan struct{})}
	id, err := f.reg.Add(alice, files.SourceSFTPQuick, files.Descriptor{Kind: files.KindSFTP}, b)
	if err != nil {
		t.Fatal(err)
	}
	if f.q.count(1) != 2 {
		t.Fatalf("quota %d", f.q.count(1))
	}
	close(b.done)
	deadline := time.Now().Add(5 * time.Second)
	for f.q.count(1) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the ended source keeps its quota")
		}
		time.Sleep(time.Millisecond)
	}
	if _, _, err := f.reg.Describe(alice, id); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("ended source still listed: %v", err)
	}
}
