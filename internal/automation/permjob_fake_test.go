package automation

import (
	"context"
	"encoding/json/jsontext"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// permTree is an in-memory source with POSIX modes.
type permTree struct {
	mu      sync.Mutex
	nodes   map[string]uint32 // st_mode
	chmods  []string
	failAt  string            // Chmod of this path fails with OUTCOME_UNKNOWN
	onChmod func(path string) // runs after each chmod (tests change the tree)
	block   chan struct{}     // when set, Lstat waits for it
	enabled bool              // the admin switch
	ident   int               // changes when the source is "reopened"
	owner   principal.Principal
	uids    map[string]uint32 // owner of a node; 1000 when absent
	login   *uint32           // LoginUID; nil when the server reports none
}

func newPermTree(p principal.Principal) *permTree {
	login := uint32(1000)
	return &permTree{enabled: true, owner: p, login: &login, uids: map[string]uint32{"/": 0}, nodes: map[string]uint32{
		"/":               0o040755,
		"/work":           0o040755,
		"/work/a.txt":     0o100600,
		"/work/b.txt":     0o100644,
		"/work/sub":       0o040700,
		"/work/sub/c.txt": 0o100600,
		"/work/link":      0o120777,
		"/work/setuid":    0o104755,
		"/other":          0o040755,
		"/other/f":        0o100600,
	}}
}

func (t *permTree) Lstat(ctx context.Context, p string) (PermEntry, error) {
	t.mu.Lock()
	block := t.block
	t.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return PermEntry{}, ctx.Err()
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.nodes[p]
	if !ok {
		return PermEntry{}, fault.New(fault.FileNotFound, "")
	}
	uid, gid := uint32(1000), uint32(1000)
	if u, ok := t.uids[p]; ok {
		uid = u
	}
	return PermEntry{Mode: m, Size: 1, ModTime: time.Unix(1700000000, 0), UID: &uid, GID: &gid}, nil
}

func (t *permTree) LoginUID(context.Context) (uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.login == nil {
		return 0, fault.New(fault.UnsafePath, "")
	}
	return *t.login, nil
}

func (t *permTree) Children(_ context.Context, dir string, fn func(string) error) error {
	t.mu.Lock()
	var names []string
	for p := range t.nodes {
		if p != "/" && path.Dir(p) == dir {
			names = append(names, path.Base(p))
		}
	}
	t.mu.Unlock()
	slices.Sort(names)
	for _, n := range names {
		if err := fn(n); err != nil {
			return err
		}
	}
	return nil
}

func (t *permTree) Chmod(_ context.Context, p string, perm uint32, _ PermEntry) error {
	t.mu.Lock()
	if p == t.failAt {
		t.mu.Unlock()
		return fault.New(fault.OutcomeUnknown, "")
	}
	m, ok := t.nodes[p]
	if !ok {
		t.mu.Unlock()
		return fault.New(fault.FileNotFound, "")
	}
	t.nodes[p] = m&^0o777 | perm
	t.chmods = append(t.chmods, p)
	hook := t.onChmod
	t.mu.Unlock()
	if hook != nil {
		hook(p)
	}
	return nil
}

func (t *permTree) mode(p string) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nodes[p] & 0o7777
}

func (t *permTree) set(p string, mode uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[p] = mode
}

// permSources holds the tree for its owner's session only.
type permSources struct{ t *permTree }

func (s permSources) Hold(_ context.Context, p principal.Principal, sourceID string) (PermSource, any, func(), error) {
	s.t.mu.Lock()
	defer s.t.mu.Unlock()
	if p.UserID != s.t.owner.UserID || p.SessionID != s.t.owner.SessionID || sourceID != "sftp-session:s1" {
		return nil, nil, nil, fault.New(fault.SourceUnavailable, "")
	}
	if !s.t.enabled {
		return nil, nil, nil, fault.New(fault.UnsupportedOperation, "")
	}
	return s.t, s.t.ident, func() {}, nil
}

func (permSources) Clean(raw string) (string, error) {
	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") || slices.Contains(strings.Split(raw, "/"), "..") {
		return "", fault.New(fault.InvalidRequest, "")
	}
	p := path.Clean(raw)
	if p == "/" {
		return "", fault.New(fault.InvalidRequest, "")
	}
	return p, nil
}

type permAudit struct {
	mu     sync.Mutex
	events []string
}

func (a *permAudit) PermissionChange(_ principal.Principal, _, operation, result, p, oldMode, newMode string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, operation+" "+result+" "+p+" "+oldMode+">"+newMode)
}

// waitFor waits until every event is recorded: the job writes its audit
// after its final state is visible.
func (a *permAudit) waitFor(t *testing.T, events ...string) {
	t.Helper()
	for range 500 {
		a.mu.Lock()
		got := slices.Clone(a.events)
		a.mu.Unlock()
		if !slices.ContainsFunc(events, func(e string) bool { return !slices.Contains(got, e) }) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	t.Fatalf("audit %v, want %v", a.events, events)
}

type permEnv struct {
	j     *PermissionJobs
	tree  *permTree
	audit *permAudit
	c     PermCaller
	clock *clock
}

func newPermEnv(t *testing.T) *permEnv {
	t.Helper()
	p := principaltest.User(5)
	e := &permEnv{tree: newPermTree(p), audit: &permAudit{}, c: PermCaller{P: p, Peer: 1},
		clock: &clock{t: time.Unix(1800000000, 0)}}
	j, err := NewPermissionJobs(PermOptions{Sources: permSources{e.tree}, Audit: e.audit, Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	e.j = j
	t.Cleanup(func() { _ = j.Shutdown(context.Background()) })
	return e
}

const src = "sftp-session:s1"

func (e *permEnv) wait(t *testing.T, id string, states ...string) jsontext.Value {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := e.j.Get(t.Context(), e.c, src, id)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(states, jsonMember(st, "state")) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("job stays %s", st)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func num(v jsontext.Value, name string) string {
	m, _ := pyjson.Get(v, name)
	return string(m)
}
