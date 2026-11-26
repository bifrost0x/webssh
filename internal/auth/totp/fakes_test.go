package totp

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type fakeAccounts struct {
	mu  sync.Mutex
	mfa map[int64]bool
}

func (a *fakeAccounts) MFARequired(_ context.Context, _ *store.Tx, id int64) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.mfa[id], nil
}

func (a *fakeAccounts) SetMFARequired(_ context.Context, _ *store.Tx, id int64, on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mfa[id] = on
	return nil
}

type fakeGates map[string]bool

func (g fakeGates) Active(_ context.Context, f string) (bool, error) { return g[f], nil }

type fakeSessions struct{ ended []string }

func (s *fakeSessions) EndRecovery(_ context.Context, _ *store.Tx, id, replacement string, basic bool) error {
	s.ended = append(s.ended, id+"|"+replacement+"|"+strconv.FormatBool(basic))
	return nil
}

type fakePasskeys struct{ n int }

func (f *fakePasskeys) Count(context.Context, *store.Tx, int64) (int, error) { return f.n, nil }

type fakePending struct {
	login     auth.PendingLogin
	completed int
	discarded int
}

func (f *fakePending) Pending(*http.Request) (auth.PendingLogin, error) { return f.login, nil }

func (f *fakePending) Complete(http.ResponseWriter, *http.Request, int64, string, auth.Assurance) (string, error) {
	f.completed++
	return "/next", nil
}

func (f *fakePending) Discard(http.ResponseWriter, *http.Request) error {
	f.discarded++
	return nil
}

type grantStepUp struct {
	action principal.Action
	target string
}

func (g *grantStepUp) Consume(_ context.Context, _ principal.Principal, action principal.Action, target, grant string) error {
	if grant != "ok" || action != g.action || target != g.target {
		return fault.New(fault.StepUpRequired, "")
	}
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

type env struct {
	svc      *Service
	accounts *fakeAccounts
	sessions *fakeSessions
	passkeys *fakePasskeys
	clock    *clock
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.Open(t, auth.Schema(), Schema())
	ring, err := keyring.Open([]byte("test-secret"), make([]byte, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{accounts: &fakeAccounts{mfa: map[int64]bool{}}, sessions: &fakeSessions{}, passkeys: &fakePasskeys{},
		clock: &clock{t: time.Date(2026, 11, 26, 12, 0, 10, 0, time.UTC)}}
	e.svc = &Service{DB: db, Ring: ring, Now: e.clock.Now, Recovery: &auth.Recovery{DB: db}, Throttle: &auth.Throttle{DB: db, Now: e.clock.Now}}
	e.svc.MFA = &auth.MFA{DB: db, Accounts: e.accounts, Sessions: e.sessions, Passkeys: e.passkeys, TOTP: e.svc,
		Gates: fakeGates{auth.FeatureTOTP: true, auth.FeaturePasskey: true, auth.FeatureRecovery: true}}
	return e
}

// codeAt returns the code of secret at the clock's time plus offset steps.
func (e *env) codeAt(t *testing.T, secret string, offset int64) string {
	t.Helper()
	key, err := otp.DecodeSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	step := otp.Step(e.clock.Now(), otp.DefaultPeriod)
	code, err := otp.TOTP(key, uint64(int64(step)+offset)) // #nosec G115 -- test steps are positive
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// enrol creates an active authenticator for p and returns its secret.
func (e *env) enrol(t *testing.T, p principal.Principal) (string, Activation) {
	t.Helper()
	en, err := e.svc.Begin(t.Context(), p, DefaultLabel)
	if err != nil {
		t.Fatal(err)
	}
	a, err := e.svc.Activate(t.Context(), p, en.Token, e.codeAt(t, en.Secret, 0))
	if err != nil {
		t.Fatal(err)
	}
	return en.Secret, a
}
