package hostops

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
)

// fakeExec answers commands like a remote host and records what it got.
type fakeExec struct {
	mu      sync.Mutex
	lines   []string
	stdins  []string
	answer  func(line, stdin string) (stdout, stderr string, status int, err error)
	release chan struct{} // when set, Exec waits for it or ctx
}

func (f *fakeExec) Exec(ctx context.Context, line string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	f.mu.Lock()
	f.lines = append(f.lines, line)
	f.stdins = append(f.stdins, string(in))
	answer, release := f.answer, f.release
	f.mu.Unlock()
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	}
	if answer == nil {
		return 0, nil
	}
	out, errOut, status, err := answer(line, string(in))
	_, _ = io.Copy(stdout, bytes.NewReader([]byte(out)))
	_, _ = io.Copy(stderr, bytes.NewReader([]byte(errOut)))
	return status, err
}

func (f *fakeExec) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lines...)
}

// fakeSessions holds live sessions by owner and ID.
type fakeSessions struct {
	mu   sync.Mutex
	live map[string]Live
	own  map[string]int64
}

func newSessions() *fakeSessions {
	return &fakeSessions{live: map[string]Live{}, own: map[string]int64{}}
}

func (s *fakeSessions) add(owner int64, id string, l Live) Live {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.Done == nil {
		l.Done = make(chan struct{})
	}
	s.live[id], s.own[id] = l, owner
	return l
}

func (s *fakeSessions) Live(owner int64, id string) (Live, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.live[id]
	return l, ok && s.own[id] == owner
}

type fakeSwitches struct{ ops, herdr bool }

func (f fakeSwitches) ServerOperationsEnabled(context.Context) bool { return f.ops }
func (f fakeSwitches) HerdrEnabled(context.Context) bool            { return f.herdr }

// fakeStepUp accepts the grant "ok" for the recorded action and target.
type fakeStepUp struct {
	mu      sync.Mutex
	calls   []string
	refused bool
}

func (f *fakeStepUp) Consume(_ context.Context, p principal.Principal, action principal.Action, target, grant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, string(action)+" "+target+" "+grant)
	if f.refused || grant != "ok" {
		return stepUpRequired
	}
	return nil
}

type fakeAudit struct {
	mu     sync.Mutex
	events []string
}

func (f *fakeAudit) Security(event string, kv ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := event
	for i := 0; i+1 < len(kv); i += 2 {
		line += " " + kv[i].(string) + "=" + toString(kv[i+1])
	}
	f.events = append(f.events, line)
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return "?"
}

type fakeProfiles map[string][2]bool

func (f fakeProfiles) HerdrOptions(_ context.Context, _ int64, id string) (bool, bool, error) {
	o := f[id]
	return o[0], o[0] && o[1], nil
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }
