package stepup

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
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

type fakeSessions struct {
	mu      sync.Mutex
	byID    map[string]SessionAssurance
	revoked map[string]bool
}

func (s *fakeSessions) Assurance(_ context.Context, p principal.Principal) (SessionAssurance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked[p.SessionID] {
		return SessionAssurance{}, fault.New(fault.AuthenticationNeeded, "")
	}
	if sa, ok := s.byID[p.SessionID]; ok {
		return sa, nil
	}
	return SessionAssurance{Level: auth.AssuranceBasic, Methods: []string{"password"}}, nil
}

type fakePasswords struct{ password string }

func (f fakePasswords) HasPassword(context.Context, int64) (bool, error) {
	return f.password != "", nil
}

func (f fakePasswords) VerifyPassword(_ context.Context, _ int64, pw string) (bool, error) {
	return f.password != "" && pw == f.password, nil
}

type fakeTOTP struct {
	enrolled map[int64]bool
	code     string
	failures int
}

func (f *fakeTOTP) Enrolled(_ context.Context, id int64) (bool, error) { return f.enrolled[id], nil }

func (f *fakeTOTP) CheckCode(_ context.Context, _ int64, code string, scope auth.Scope) error {
	if scope != auth.ScopeStepUp {
		return errors.New("wrong scope")
	}
	if f.failures >= 3 {
		return auth.Throttled(30 * time.Second)
	}
	if code != f.code {
		f.failures++
		return fault.New(fault.AuthFailed, "")
	}
	return nil
}

type fakePasskeys struct {
	enrolled map[int64]bool
	bindings []string
}

func (f *fakePasskeys) Enrolled(_ context.Context, id int64) (bool, error) {
	return f.enrolled[id], nil
}

func (f *fakePasskeys) AssertionOptions(_ context.Context, _ int64, binding string) (jsontext.Value, error) {
	f.bindings = append(f.bindings, binding)
	return jsontext.Value(`{"challenge":"abc"}`), nil
}

func (f *fakePasskeys) VerifyAssertion(_ context.Context, _ int64, binding string, credential jsontext.Value) error {
	if len(f.bindings) == 0 || f.bindings[len(f.bindings)-1] != binding || string(credential) != `{"id":"good"}` {
		return errors.New("assertion refused")
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
	totp     *fakeTOTP
	passkeys *fakePasskeys
	clock    *clock
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ring, err := keyring.Open([]byte("test-secret"), make([]byte, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		accounts: &fakeAccounts{mfa: map[int64]bool{}},
		sessions: &fakeSessions{byID: map[string]SessionAssurance{}, revoked: map[string]bool{}},
		totp:     &fakeTOTP{enrolled: map[int64]bool{}, code: "123456"},
		passkeys: &fakePasskeys{enrolled: map[int64]bool{}},
		clock:    &clock{t: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)},
	}
	e.svc = &Service{
		DB: storetest.Open(t, Schema()), Ring: ring, Sessions: e.sessions, Accounts: e.accounts,
		Gates:     fakeGates{auth.FeatureTOTP: true, auth.FeaturePasskey: true, auth.FeatureRecovery: true},
		Passwords: fakePasswords{password: "secret"}, TOTP: e.totp, Passkeys: e.passkeys,
		RecentWindow: 300 * time.Second, Now: e.clock.Now, Logger: slog.New(slog.DiscardHandler),
	}
	return e
}
