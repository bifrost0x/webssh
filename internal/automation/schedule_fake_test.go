package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// fakeWorkflows stands in for the run side of automation (AU1): one
// runbook and a fixed set of targets per user; Current compares the
// snapshot with what is stored now.
type fakeWorkflows struct {
	mu       sync.Mutex
	book     jsontext.Value
	targets  []jsontext.Value
	keys     map[string]string
	started  []ScheduledRun
	startErr error
	manual   []func(context.Context) error
}

func newFakeWorkflows() *fakeWorkflows {
	return &fakeWorkflows{
		book: jsontext.Value(`{"id":"b1","name":"Nächtlich ✓","steps":[{"name":"id","command":"id","timeout":30,"sudo":false}],"stop_on_error":true}`),
		targets: []jsontext.Value{
			jsontext.Value(`{"id":"p1","name":"Host 1","host":"h1.example","port":22,"username":"op","auth_type":"key","key_id":"k1","jump_host_id":null,"kind":"ssh"}`),
			jsontext.Value(`{"id":"p2","name":"Host 2","host":"h2.example","port":2222,"username":"op","auth_type":"password","key_id":null,"jump_host_id":null,"kind":"ssh","group":"web"}`),
		},
		keys: map[string]string{"p1": "digest-k1"},
	}
}

func (f *fakeWorkflows) Review(_ context.Context, _ principal.Principal, rq jsontext.Value) (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if jsonMember(rq, "runbook_id") != "b1" {
		return Snapshot{}, fault.New(fault.NotFound, "")
	}
	return Snapshot{Book: f.book, Targets: slices.Clone(f.targets), KeyDigests: f.keys}, nil
}

func (f *fakeWorkflows) Current(_ context.Context, _ int64, s Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !sameJSON(s.Book, f.book) || len(s.Targets) != len(f.targets) {
		return fault.New(fault.PreviewChanged, "")
	}
	for i := range s.Targets {
		if !sameJSON(s.Targets[i], f.targets[i]) {
			return fault.New(fault.PreviewChanged, "")
		}
	}
	for k, v := range s.KeyDigests {
		if f.keys[k] != v {
			return fault.New(fault.PreviewChanged, "")
		}
	}
	return nil
}

func (f *fakeWorkflows) PrepareManual(_ context.Context, _ principal.Principal, _ Snapshot, check func(context.Context) error) (jsontext.Value, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manual = append(f.manual, check)
	return jsontext.Value(`{"intent":"manual"}`), nil
}

func (f *fakeWorkflows) StartScheduled(_ context.Context, run ScheduledRun) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.started = append(f.started, run)
	return nil
}

func (f *fakeWorkflows) runs() []ScheduledRun {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.started)
}

func (f *fakeWorkflows) changeTarget(i int, v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets[i] = jsontext.Value(v)
}

type fakeAccounts struct {
	mu sync.Mutex
	m  map[int64]AccountBinding
}

func (a *fakeAccounts) ScheduleAccount(_ context.Context, id int64) (AccountBinding, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.m[id]
	if !ok {
		return AccountBinding{}, fault.New(fault.NotFound, "")
	}
	return b, nil
}

func (a *fakeAccounts) update(id int64, f func(*AccountBinding)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.m[id]
	f(&b)
	a.m[id] = b
}

func (a *fakeAccounts) remove(id int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.m, id)
}

type fakePolicy struct {
	mu       sync.Mutex
	enabled  bool
	revision string
}

func (p *fakePolicy) AutomationPolicy(context.Context) (bool, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled, p.revision, nil
}

func (p *fakePolicy) set(enabled bool, revision string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled, p.revision = enabled, revision
}

// fakePasswords binds to a version per hop id; a missing version is no
// assigned password.
type fakePasswords struct {
	mu       sync.Mutex
	versions map[string]string
}

func (f *fakePasswords) ScheduleBinding(_ context.Context, _ int64, hops []jsontext.Value) (jsontext.Value, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := `{`
	for i, h := range hops {
		v, ok := f.versions[jsonMember(h, "id")]
		if !ok {
			return nil, fault.New(fault.CredentialMissing, "")
		}
		if i > 0 {
			out += ","
		}
		out += `"` + jsonMember(h, "id") + `":"` + v + `"`
	}
	return jsontext.Value(out + `}`), nil
}

func (f *fakePasswords) SchedulePassword(ctx context.Context, userID int64, hop, approved jsontext.Value) ([]byte, error) {
	if _, err := f.ScheduleBinding(ctx, userID, []jsontext.Value{hop}); err != nil {
		return nil, err
	}
	if len(approved) == 0 {
		return nil, errors.New("no approved binding")
	}
	return []byte("secret"), nil
}

func (f *fakePasswords) set(id, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions[id] = version
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.t = t }

type audit struct {
	mu     sync.Mutex
	events []string
}

func (a *audit) Security(event string, _ ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
}

type scheduleEnv struct {
	s         *Schedules
	wf        *fakeWorkflows
	accounts  *fakeAccounts
	policy    *fakePolicy
	passwords *fakePasswords
	stepUp    *principaltest.StepUp
	clock     *clock
	audit     *audit
	p         principal.Principal
}

func newScheduleEnv(t *testing.T) *scheduleEnv {
	t.Helper()
	e := &scheduleEnv{
		wf:        newFakeWorkflows(),
		accounts:  &fakeAccounts{m: map[int64]AccountBinding{7: {Incarnation: "2026-01-01T00:00:00", AuthGeneration: 3, Epoch: "e1"}}},
		policy:    &fakePolicy{enabled: true, revision: "r1"},
		passwords: &fakePasswords{versions: map[string]string{"p2": "v1"}},
		stepUp:    &principaltest.StepUp{},
		clock:     &clock{t: time.Date(2026, 3, 1, 8, 30, 0, 0, time.UTC)},
		audit:     &audit{},
		p:         principaltest.User(7),
	}
	s, err := NewSchedules(ScheduleOptions{
		DB: storetest.Open(t, Schema()), Workflows: e.wf, Accounts: e.accounts, Policy: e.policy,
		Passwords: e.passwords, StepUp: e.stepUp, Audit: e.audit, Now: e.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.s = s
	return e
}

// approve reviews and approves a schedule and returns its id.
func (e *scheduleEnv) approve(t *testing.T, cron, zone string) string {
	t.Helper()
	pv, err := e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","profile_ids":["p1","p2"],"cron":"`+cron+`","timezone":"`+zone+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	token := jsonMember(pv, "intent")
	e.stepUp.Issue(e.p, principal.ActionAutomationSchedule, token, "grant-"+token)
	out, err := e.s.Approve(t.Context(), e.p, token, "2", "grant-"+token)
	if err != nil {
		t.Fatal(err)
	}
	return jsonMember(out, "id")
}
