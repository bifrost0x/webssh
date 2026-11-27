package terminal

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// fakeHerdr grants per profile: [overview, session].
type fakeHerdr map[string][2]bool

func (f fakeHerdr) Grants(_ context.Context, _ int64, id string) (bool, bool) {
	g := f[id]
	return g[0], g[0] && g[1]
}

func (fakeHerdr) Commands() (string, string) { return "probe-herdr", "run-herdr" }

// herdrHost answers the Herdr lookup with probe.
type herdrHost struct {
	*fakeHost
	probe int
}

func (h herdrHost) run(ctx context.Context, line string, d time.Duration) (int, []byte, error) {
	if line == "probe-herdr" {
		h.mu.Lock()
		h.lines = append(h.lines, line)
		h.mu.Unlock()
		return h.probe, nil, nil
	}
	return h.fakeHost.run(ctx, line, d)
}

func newHerdrManager(t *testing.T, grants fakeHerdr, probe int) (*Manager, *fakeShells, *[]*fakeHost) {
	t.Helper()
	shells := &fakeShells{}
	saved := client.Target{Owner: 1, Hop: client.Hop{Host: "h.example", Port: 22, User: "u"}}
	profiles := fakeProfiles{}
	for id := range grants {
		tg := saved
		tg.Display.ProfileID = id
		profiles[id] = tg
	}
	m, err := New(Config{}, Deps{Quotas: testQuotas(t, 10, 5), Shells: shells, Profiles: profiles, Log: slog.New(slog.DiscardHandler),
		DB: storetest.Open(t, Schema()), Herdr: grants})
	if err != nil {
		t.Fatal(err)
	}
	hosts := &[]*fakeHost{}
	m.dialHost = func(context.Context, client.Target, client.Interaction) (remoteHost, error) {
		h := &fakeHost{}
		*hosts = append(*hosts, h)
		return herdrHost{h, probe}, nil
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return m, shells, hosts
}

func herdrOpen(t *testing.T, m *Manager, profile string, mutate func(*protocol.OpenTarget)) (protocol.TerminalOpened, *protocol.Error) {
	t.Helper()
	req := openReq(1, "r")
	req.Target = protocol.OpenTarget{ProfileID: profile, AuthType: "password", UseHerdr: true}
	if mutate != nil {
		mutate(&req.Target)
	}
	var res protocol.TerminalOpened
	werr := call(t, m, user(t, 1), protocol.TypeTerminalOpen, req, &res)
	return res, werr
}

func TestHerdrSessionMode(t *testing.T) {
	m, shells, hosts := newHerdrManager(t, fakeHerdr{"h": {true, true}, "o": {true, false}, "n": {}}, 0)
	res, werr := herdrOpen(t, m, "h", nil)
	if werr != nil || !res.Info.Herdr || !res.Info.UseHerdr {
		t.Fatalf("%+v %+v", res.Info, werr)
	}
	h := (*hosts)[0]
	if got := h.ran(); len(got) != 1 || got[0] != "probe-herdr" || h.started[0] != "run-herdr" {
		t.Fatalf("ran %q started %q", got, h.started)
	}
	if len(shells.targets) != 0 {
		t.Fatal("login shell opened as well")
	}
	// Overview only: the login shell, and the overview flag.
	res, werr = herdrOpen(t, m, "o", nil)
	if werr != nil || !res.Info.Herdr || res.Info.UseHerdr || len(*hosts) != 1 {
		t.Fatalf("overview only: %+v %+v", res.Info, werr)
	}
	// Neither: nothing the browser sends turns Herdr on.
	res, werr = herdrOpen(t, m, "n", nil)
	if werr != nil || res.Info.Herdr || res.Info.UseHerdr {
		t.Fatalf("no grant: %+v %+v", res.Info, werr)
	}
	// tmux and Herdr together are refused, as in the Python release.
	_, werr = herdrOpen(t, m, "h", func(o *protocol.OpenTarget) { o.UseTmux = true })
	if werr == nil || werr.Code != fault.InvalidValue || werr.Message != "tmux and Herdr cannot be combined" {
		t.Fatalf("tmux and Herdr: %+v", werr)
	}
	// A typed connection has no saved host: no Herdr.
	req := openReq(2, "typed")
	req.Target.UseHerdr = true
	var typed protocol.TerminalOpened
	if werr := call(t, m, user(t, 1), protocol.TypeTerminalOpen, req, &typed); werr != nil || typed.Info.UseHerdr || typed.Info.Herdr {
		t.Fatalf("typed: %+v %+v", typed.Info, werr)
	}
}

func TestHerdrMissingFallsBackToTheLoginShell(t *testing.T) {
	m, _, hosts := newHerdrManager(t, fakeHerdr{"h": {true, true}}, 1)
	res, werr := herdrOpen(t, m, "h", nil)
	if werr != nil || res.Info.UseHerdr || !res.Info.Herdr {
		t.Fatalf("%+v %+v", res.Info, werr)
	}
	if h := (*hosts)[0]; len(h.started) != 1 || h.started[0] != "" {
		t.Fatalf("started %q", h.started)
	}
	// The session runs on a connection it owns; commands for it reach the
	// host only if it can run them.
	live, ok := m.Live(1, res.SessionID)
	if !ok || live.ProfileID != "h" || !live.Herdr {
		t.Fatalf("live %+v %v", live, ok)
	}
	if _, err := live.Exec.Exec(t.Context(), "id", nil, nil, nil); !fault.Is(err, fault.Unavailable) {
		t.Fatalf("exec on a fake host: %v", err)
	}
	if _, ok := m.Live(2, res.SessionID); ok {
		t.Fatal("another user sees the session")
	}
}

func TestLiveNeedsAnExecutor(t *testing.T) {
	m, _, _ := newHerdrManager(t, fakeHerdr{}, 0)
	res := open(t, m, user(t, 1), 1)
	if _, ok := m.Live(1, res.SessionID); ok {
		t.Fatal("a fake shell cannot run commands")
	}
	if _, ok := m.Live(1, "missing"); ok {
		t.Fatal("missing session")
	}
}
