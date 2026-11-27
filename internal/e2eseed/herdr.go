package e2eseed

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Realtime message types of the Herdr hooks (tests/e2e/herdr_fixture.py).
const (
	TypeHerdrSessions  = "e2e.herdr_sessions"
	TypeHerdrExecCount = "e2e.herdr_exec_count"
)

// maxHerdrFixtures bounds the profiles of one request, as in the Python
// fixture.
const maxHerdrFixtures = 12

// HerdrSnapshotFile is the recorded snapshot of the tested Herdr release,
// relative to the directory of the seed file.
const HerdrSnapshotFile = "../fixtures/herdr_snapshot.json"

// herdrSnapshotMarker identifies the snapshot command of internal/hostops;
// the fixture refuses every other command, so a test sees any command
// that should not have run.
const herdrSnapshotMarker = "; herdr api snapshot & p=$!; "

// HerdrSessions is provided by internal/terminal in the e2e build: fixture
// sessions of the owner's saved hosts that the terminal treats as
// connected and whose commands run on the executor exec returns.
type HerdrSessions interface {
	// ReplaceHerdrFixtures ends the owner's earlier Herdr fixtures and
	// creates one connected session per saved host. A profile that is not
	// the owner's fails the whole request before anything is created.
	ReplaceHerdrFixtures(ctx context.Context, owner int64, profileIDs []string, exec func(sessionID string) remotecmd.Executor) ([]string, error)
}

// HerdrSessionsRequest is the payload of TypeHerdrSessions.
type HerdrSessionsRequest struct {
	ProfileIDs []string `json:"profile_ids"`
}

// Validate applies the bound of the Python fixture.
func (r *HerdrSessionsRequest) Validate() error {
	if len(r.ProfileIDs) > maxHerdrFixtures {
		return errors.New("at most 12 profile ids")
	}
	return nil
}

// HerdrSessionsResult is the result of TypeHerdrSessions; OK false
// answers a request the fixture cannot serve, as the Python hook does.
type HerdrSessionsResult struct {
	OK         bool     `json:"ok"`
	SessionIDs []string `json:"session_ids,omitempty"`
}

// HerdrExecCount is the result of TypeHerdrExecCount.
type HerdrExecCount struct {
	OK    bool `json:"ok"`
	Count int  `json:"count"`
}

// LoadHerdrSnapshot reads the recorded snapshot and appends the hostile
// agent of the Python fixture; the result is the command's output.
func LoadHerdrSnapshot(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- a path of the checked-in test tree
	if err != nil {
		return nil, fmt.Errorf("e2e: herdr snapshot: %w", err)
	}
	var doc struct {
		ID     jsontext.Value `json:"id"`
		Result struct {
			Snapshot map[string]jsontext.Value `json:"snapshot"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("e2e: herdr snapshot: %w", err)
	}
	var agents []jsontext.Value
	if err := json.Unmarshal(doc.Result.Snapshot["agents"], &agents); err != nil {
		return nil, fmt.Errorf("e2e: herdr snapshot agents: %w", err)
	}
	hostile, err := json.Marshal(map[string]string{
		"agent": "builder", "agent_status": "working",
		"name":    `<img src=x onerror="window.__herdrInjected=1">`,
		"cwd":     `/srv/"><script>window.__herdrInjected=2</script>`,
		"pane_id": "w1:p9",
	})
	if err != nil {
		return nil, err
	}
	agents = append(agents, hostile)
	if doc.Result.Snapshot["agents"], err = json.Marshal(agents); err != nil {
		return nil, err
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// herdrFixtures counts the snapshot commands per fixture session.
type herdrFixtures struct {
	sessions HerdrSessions
	payload  []byte

	mu     sync.Mutex
	owners map[string]int64
	counts map[string]int
}

func newHerdrFixtures(sessions HerdrSessions, payload []byte) *herdrFixtures {
	return &herdrFixtures{sessions: sessions, payload: payload, owners: map[string]int64{}, counts: map[string]int{}}
}

// HerdrRoutes returns the counterparts of the e2e_herdr_sessions and
// e2e_herdr_exec_count hooks.
func HerdrRoutes(sessions HerdrSessions, snapshot []byte) []protocol.Route {
	f := newHerdrFixtures(sessions, snapshot)
	return []protocol.Route{
		protocol.Handle(TypeHerdrSessions, protocol.Spec{Mutates: true}, f.replace),
		protocol.Handle(TypeHerdrExecCount, protocol.Spec{}, f.count),
	}
}

func (f *herdrFixtures) replace(ctx context.Context, _ protocol.Peer, req HerdrSessionsRequest) (HerdrSessionsResult, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return HerdrSessionsResult{}, err
	}
	f.forget(p.UserID)
	ids, err := f.sessions.ReplaceHerdrFixtures(ctx, p.UserID, req.ProfileIDs, f.executor)
	if err != nil {
		return HerdrSessionsResult{}, nil
	}
	f.mu.Lock()
	for _, id := range ids {
		f.owners[id] = p.UserID
	}
	f.mu.Unlock()
	if ids == nil {
		ids = []string{}
	}
	return HerdrSessionsResult{OK: true, SessionIDs: ids}, nil
}

func (f *herdrFixtures) forget(owner int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, o := range f.owners {
		if o == owner {
			delete(f.owners, id)
			delete(f.counts, id)
		}
	}
}

func (f *herdrFixtures) count(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (HerdrExecCount, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return HerdrExecCount{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for id, o := range f.owners {
		if o == p.UserID {
			n += f.counts[id]
		}
	}
	return HerdrExecCount{OK: true, Count: n}, nil
}

func (f *herdrFixtures) executor(sessionID string) remotecmd.Executor {
	return herdrExec{f: f, session: sessionID}
}

// herdrExec answers the snapshot command with the recorded snapshot.
type herdrExec struct {
	f       *herdrFixtures
	session string
}

func (e herdrExec) Exec(ctx context.Context, command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
	if !strings.Contains(command, herdrSnapshotMarker) {
		return -1, errors.New("e2e: unexpected command on the Herdr fixture")
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	e.f.mu.Lock()
	e.f.counts[e.session]++
	e.f.mu.Unlock()
	if _, err := stdout.Write(e.f.payload); err != nil {
		return -1, err
	}
	return 0, nil
}

// herdrSnapshotPath resolves HerdrSnapshotFile next to the seed file.
func herdrSnapshotPath(seedPath string) string {
	return filepath.Join(filepath.Dir(seedPath), filepath.FromSlash(HerdrSnapshotFile))
}
