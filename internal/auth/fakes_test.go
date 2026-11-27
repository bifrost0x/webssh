package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type fakeAccounts struct {
	mu  sync.Mutex
	mfa map[int64]bool
}

func (a *fakeAccounts) MFARequired(_ context.Context, _ *store.Tx, userID int64) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.mfa[userID], nil
}

func (a *fakeAccounts) SetMFARequired(_ context.Context, _ *store.Tx, userID int64, on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mfa == nil {
		a.mfa = map[int64]bool{}
	}
	a.mfa[userID] = on
	return nil
}

type fakeGates map[string]bool

func (g fakeGates) Active(_ context.Context, f string) (bool, error) { return g[f], nil }

type fakeTOTP struct {
	mu    sync.Mutex
	count map[int64]int
}

func (f *fakeTOTP) Count(_ context.Context, _ *store.Tx, userID int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count[userID], nil
}

func (f *fakeTOTP) RemoveAll(_ context.Context, _ *store.Tx, userID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.count, userID)
	return nil
}

type fakeSessions struct {
	mu    sync.Mutex
	ended []string
}

func (s *fakeSessions) EndRecovery(_ context.Context, _ *store.Tx, sessionID, replacement string, basic bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = append(s.ended, sessionID+"|"+replacement+"|"+map[bool]string{true: "basic", false: "keep"}[basic])
	return nil
}

type fakePending struct {
	login     PendingLogin
	err       error
	completed []string
	discarded int
}

func (f *fakePending) Pending(*http.Request) (PendingLogin, error) { return f.login, f.err }

func (f *fakePending) Complete(_ http.ResponseWriter, _ *http.Request, userID int64, factor string, a Assurance) (string, error) {
	f.completed = append(f.completed, itoa(userID)+"|"+factor+"|"+string(a))
	return "/", nil
}

func (f *fakePending) Discard(http.ResponseWriter, *http.Request) error {
	f.discarded++
	return nil
}

type countingLimiter struct {
	mu    sync.Mutex
	hits  map[string]int
	limit int
}

func (l *countingLimiter) Allow(key string, _ Rule) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string]int{}
	}
	l.hits[key]++
	return l.hits[key] <= l.limit, 0
}

func (l *countingLimiter) AllowAccount(key string, r Rule) (bool, time.Duration) {
	return l.Allow(key, r)
}

type recordingAudit struct {
	mu     sync.Mutex
	events []string
}

func (a *recordingAudit) Security(_ context.Context, _ slog.Level, event string, _ ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
}

// grantStepUp accepts exactly the grant "ok" for the expected action and
// target and records refusals.
type grantStepUp struct {
	action principal.Action
	target string
	used   bool
}

func (g *grantStepUp) Consume(_ context.Context, _ principal.Principal, action principal.Action, target, grant string) error {
	if grant != "ok" || action != g.action || target != g.target || g.used {
		return fault.New(fault.StepUpRequired, "")
	}
	g.used = true
	return nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func openDB(t *testing.T) *store.DB {
	t.Helper()
	return storetest.Open(t, Schema())
}

func codeOf(err error) fault.Code {
	if fe, ok := errors.AsType[*fault.Error](err); ok {
		return fe.Code
	}
	return ""
}
