package terminal

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

func (h *fakeHost) input() string {
	h.mu.Lock()
	pty := h.pty
	h.mu.Unlock()
	if pty == nil {
		return ""
	}
	pty.mu.Lock()
	defer pty.mu.Unlock()
	return pty.input.String()
}

func startupReq(ch uint32, rid string, s protocol.Startup) protocol.TerminalOpen {
	req := openReq(ch, rid)
	req.Target.Startup = &s
	return req
}

func TestStartupCommandsAreTheFirstInput(t *testing.T) {
	r := newTmuxRig(t)
	peer := user(t, 1)
	res := openTmux(t, r, peer, startupReq(1, "r1", protocol.Startup{Mode: startupFreeText, Commands: "cd /srv\r\nmake\n\n"}))
	h := r.host(t, 0)
	eventually(t, "startup input", func() bool { return h.input() == "cd /srv\rmake\r" })
	// Typed input follows the startup commands.
	if err := r.m.HandleBinary(peer, input(1, 1, "x", false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "typed input", func() bool { return h.input() == "cd /srv\rmake\rx" })
	_ = res
}

func TestStartupCommandsSkipATmuxReattach(t *testing.T) {
	r := newTmuxRig(t)
	r.seed(t, detachedRow("old", "webssh_u_h_22_0a0b0c0d"))
	req := tmuxOpen(1, "r1", "webssh_u_h_22_0a0b0c0d")
	req.Target.Startup = &protocol.Startup{Commands: "make"}
	res := openTmux(t, r, user(t, 1), req)
	if res.Info.TmuxSessionName != "webssh_u_h_22_0a0b0c0d" {
		t.Fatalf("not reattached: %+v", res.Info)
	}
	// A new tmux session runs them.
	req = tmuxOpen(2, "r2", "")
	req.Target.Startup = &protocol.Startup{Commands: "make"}
	openTmux(t, r, user(t, 1), req)
	eventually(t, "startup in the new tmux session", func() bool { return r.host(t, 1).input() == "make\r" })
	if got := r.host(t, 0).input(); got != "" {
		t.Fatalf("reattach got startup input %q", got)
	}
}

func TestStartupErrorsRefuseTheConnection(t *testing.T) {
	r := newTmuxRig(t)
	for _, c := range []struct {
		s    protocol.Startup
		code fault.Code
		msg  string
	}{
		{protocol.Startup{Mode: "shell"}, fault.InvalidValue, "Invalid post-connect command mode"},
		{protocol.Startup{Mode: startupFreeText, CommandID: "c"}, fault.InvalidValue, "Conflicting post-connect command configuration"},
		{protocol.Startup{Commands: "a\x00"}, fault.InvalidValue, "Startup commands must not contain NUL bytes"},
		{protocol.Startup{CommandID: "c"}, fault.NotAvailableInPreview, ""},
	} {
		werr := call(t, r.m, user(t, 1), protocol.TypeTerminalOpen, startupReq(1, "r", c.s), nil)
		if werr == nil || werr.Code != c.code || c.msg != "" && werr.Message != c.msg {
			t.Errorf("%+v: %+v", c.s, werr)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hosts) != 0 {
		t.Fatal("dialled before the startup check")
	}
}

type stubCommands struct{}

func (stubCommands) Command(_ context.Context, owner int64, id string) (string, string, error) {
	if owner != 1 || id != "c1" {
		return "", "", fault.New(fault.NotFound, "Command not found")
	}
	return "ls", "-la", nil
}

func (stubCommands) ResolveSet(_ context.Context, owner int64, id string) (string, error) {
	if owner != 1 || id != "s1" {
		return "", fault.New(fault.NotFound, "Command set not found")
	}
	return "cd /srv && make", nil
}

func TestStartupCommandAndSetComeFromTheOwnersLibrary(t *testing.T) {
	r := newTmuxRig(t)
	r.m.commands = stubCommands{}
	override := "-h"
	openTmux(t, r, user(t, 1), startupReq(1, "r1", protocol.Startup{CommandID: "c1", ParametersOverride: &override}))
	openTmux(t, r, user(t, 1), startupReq(2, "r2", protocol.Startup{Mode: startupSet, CommandSetID: "s1"}))
	eventually(t, "command", func() bool { return r.host(t, 0).input() == "ls -h\r" })
	eventually(t, "set", func() bool { return r.host(t, 1).input() == "cd /srv && make\r" })
	werr := call(t, r.m, user(t, 2), protocol.TypeTerminalOpen, startupReq(3, "r3", protocol.Startup{CommandID: "c1"}), nil)
	if werr == nil || werr.Code != fault.NotFound {
		t.Fatalf("another user's command: %+v", werr)
	}
}

type grants struct{ overview, session atomic.Bool }

func (g *grants) Overview(_ context.Context, owner int64, id string) bool {
	return owner == 1 && id == "p1" && g.overview.Load()
}

func (g *grants) SessionMode(_ context.Context, owner int64, id string) bool {
	return owner == 1 && id == "p1" && g.session.Load()
}

func herdrRig(t *testing.T) (*tmuxRig, *grants) {
	r := newTmuxRig(t)
	g := &grants{}
	g.overview.Store(true)
	g.session.Store(true)
	r.m.herdr = g
	r.m.profiles = fakeProfiles{"p1": {Owner: 1, Hop: client.Hop{Host: "h", Port: 22, User: "u"}}}
	return r, g
}

func herdrReq(ch uint32, rid string) protocol.TerminalOpen {
	req := openReq(ch, rid)
	req.Target.ProfileID, req.Target.UseHerdr = "p1", true
	return req
}

func TestHerdrSessionModeRunsHerdr(t *testing.T) {
	r, _ := herdrRig(t)
	res := openTmux(t, r, user(t, 1), herdrReq(1, "r1"))
	h := r.host(t, 0)
	if !res.Info.Herdr || !res.Info.UseHerdr || h.started[0] != herdrSessionCommand || !h.ranAny("command -v herdr") {
		t.Fatalf("herdr: %+v started %q", res.Info, h.started)
	}
	// Closing a Herdr session stops nothing on the host.
	call(t, r.m, user(t, 1), protocol.TypeTerminalClose, protocol.SessionRef{SessionID: res.SessionID}, nil)
	eventually(t, "closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
	if len(h.ran()) != 1 {
		t.Fatalf("commands after close: %q", h.ran())
	}
}

func TestHerdrFallsBackAndIsNeverGrantedByTheBrowser(t *testing.T) {
	r, g := herdrRig(t)
	r.next = func() *fakeHost { return &fakeHost{noHerdr: true} }
	res := openTmux(t, r, user(t, 1), herdrReq(1, "r1"))
	if !res.Info.Herdr || res.Info.UseHerdr || r.host(t, 0).started[0] != "" {
		t.Fatalf("missing herdr: %+v", res.Info)
	}
	r.next = func() *fakeHost { return &fakeHost{} }
	// Only the overview: the session mode is not granted.
	g.session.Store(false)
	res = openTmux(t, r, user(t, 1), herdrReq(2, "r2"))
	if !res.Info.Herdr || res.Info.UseHerdr || r.host(t, 1).ranAny("herdr") {
		t.Fatalf("overview only: %+v", res.Info)
	}
	// A typed connection never gets Herdr, whatever it asks for.
	req := openReq(3, "r3")
	req.Target.UseHerdr = true
	res = openTmux(t, r, user(t, 1), req)
	if res.Info.Herdr || res.Info.UseHerdr {
		t.Fatalf("typed connection: %+v", res.Info)
	}
	// Another user's saved host does not resolve at all.
	if werr := call(t, r.m, user(t, 2), protocol.TypeTerminalOpen, herdrReq(4, "r4"), nil); werr == nil || werr.Code != fault.NotFound {
		t.Fatalf("foreign host: %+v", werr)
	}
}

func TestHerdrExcludesTmuxAndStartupCommands(t *testing.T) {
	r, _ := herdrRig(t)
	req := herdrReq(1, "r1")
	req.Target.UseTmux = true
	if werr := call(t, r.m, user(t, 1), protocol.TypeTerminalOpen, req, nil); werr == nil || werr.Message != "tmux and Herdr cannot be combined" {
		t.Fatalf("tmux: %+v", werr)
	}
	req = herdrReq(2, "r2")
	req.Target.Startup = &protocol.Startup{Commands: "ls"}
	if werr := call(t, r.m, user(t, 1), protocol.TypeTerminalOpen, req, nil); werr == nil ||
		werr.Message != "Herdr session mode cannot be combined with startup commands" {
		t.Fatalf("startup: %+v", werr)
	}
	// An empty startup text is no startup command (Python checks the text).
	req = herdrReq(3, "r3")
	req.Target.Startup = &protocol.Startup{Mode: startupFreeText, Commands: ""}
	if res := openTmux(t, r, user(t, 1), req); !res.Info.UseHerdr {
		t.Fatalf("empty startup: %+v", res.Info)
	}
}

func TestGatewayTmuxSessionsUseTheGatewayName(t *testing.T) {
	r := newTmuxRig(t)
	var got []any
	r.m.gatewayTmuxName = func(prefix, host string, port int, selector string, userID int64) (string, error) {
		got = []any{prefix, host, port, selector, userID}
		return "webssh_wg_0123456789abcdef_" + strings.Repeat("a", 32), nil
	}
	r.m.variants = passVariants{}
	req := tmuxOpen(1, "r1", "")
	req.Target.Username = "alice:prod"
	res := openTmux(t, r, user(t, 1), req)
	if res.Info.TmuxSessionName != "webssh_wg_0123456789abcdef_"+strings.Repeat("a", 32) ||
		got[0] != "webssh" || got[1] != "h.example" || got[2] != 22 || got[3] != "alice:prod" || got[4] != int64(1) {
		t.Fatalf("gateway name %+v from %v", res.Info, got)
	}
}

func TestTailscaleTmuxForcesUTF8(t *testing.T) {
	r := newTmuxRig(t)
	r.m.variants = passVariants{}
	req := tmuxOpen(1, "r1", "")
	req.Target.AuthType, req.Target.Password = protocol.AuthTailscale, ""
	openTmux(t, r, user(t, 1), req)
	if s := r.host(t, 0).started[0]; !strings.HasPrefix(s, "env LANG=C.UTF-8 LC_ALL=C.UTF-8 tmux -u new-session -s ") {
		t.Fatalf("tailscale tmux %q", s)
	}
}

// passVariants accepts every gateway and Tailscale attempt unchanged.
type passVariants struct{}

func (passVariants) Prepare(ctx context.Context, a VariantAttempt) (client.Target, context.Context, func(), error) {
	return a.Target, ctx, func() {}, nil
}

func (passVariants) Interact(ctx context.Context, _ VariantAttempt) (client.Challenger, context.Context, func(), error) {
	return nil, ctx, func() {}, nil
}

func TestDisplayNameOfANewPersistentSession(t *testing.T) {
	r := newTmuxRig(t)
	req := tmuxOpen(1, "r1", "")
	req.Target.DisplayName = "  Build server  "
	res := openTmux(t, r, user(t, 1), req)
	rows := r.rows(t, 1)
	if res.Info.DisplayName != "Build server" || len(rows) != 1 || rows[0].DisplayName.String != "Build server" {
		t.Fatalf("display name %+v %+v", res.Info, rows)
	}
	// Without tmux the name is ignored, as display_name was.
	req = openReq(2, "r2")
	req.Target.DisplayName = "x"
	if res := openTmux(t, r, user(t, 1), req); res.Info.DisplayName != "" {
		t.Fatalf("plain session named %q", res.Info.DisplayName)
	}
	// A reattach without a name keeps the stored one.
	r.seed(t, detachedRow("old", "webssh_u_h_22_0a0b0c0d"))
	if res := openTmux(t, r, user(t, 1), tmuxOpen(3, "r3", "webssh_u_h_22_0a0b0c0d")); res.Info.DisplayName != "Build" {
		t.Fatalf("reattach name %q", res.Info.DisplayName)
	}
}

func TestSessionConnIsOwnedAndEndsWithTheSession(t *testing.T) {
	r := newTmuxRig(t)
	res := openTmux(t, r, user(t, 1), openReq(1, "r1"))
	// The fake host has no client connection: not_found, like a foreign
	// session.
	if _, err := r.m.SessionConn(1, res.SessionID); fault.CodeOf(err) != fault.NotFound {
		t.Fatalf("fake host: %v", err)
	}
	if _, err := r.m.SessionConn(2, res.SessionID); fault.CodeOf(err) != fault.NotFound {
		t.Fatalf("foreign session: %v", err)
	}
	if _, err := r.m.SessionConn(1, "missing"); fault.CodeOf(err) != fault.NotFound {
		t.Fatalf("missing session: %v", err)
	}
}

func TestPlanHerdrNeedsBothGrants(t *testing.T) {
	g := &grants{}
	g.overview.Store(true)
	m := &Manager{herdr: g}
	target := client.Target{Display: client.Display{ProfileID: "p1"}}
	p, err := m.planHerdr(t.Context(), 1, protocol.OpenTarget{UseHerdr: true}, target, "")
	if err != nil || !p.overview || p.session {
		t.Fatalf("overview only: %+v %v", p, err)
	}
	g.session.Store(true)
	if p, _ = m.planHerdr(t.Context(), 1, protocol.OpenTarget{}, target, ""); p.session {
		t.Fatal("session mode without asking")
	}
	if p, _ = m.planHerdr(t.Context(), 1, protocol.OpenTarget{UseHerdr: true}, target, ""); !p.session {
		t.Fatal("granted session mode refused")
	}
}

// The largest startup text that normalization accepts fits terminal.open.
func TestLargestStartupFitsTheOpenRequest(t *testing.T) {
	r := newTmuxRig(t)
	text := strings.Repeat("\"", 4095) + "\n"
	override := strings.Repeat("\\", 4096)
	req := startupReq(1, "r1", protocol.Startup{Commands: text, ParametersOverride: &override})
	req.Target.DisplayName = strings.Repeat("\"", 4096)
	openTmux(t, r, user(t, 1), req)
	eventually(t, "startup input", func() bool { return r.host(t, 0).input() == strings.Repeat("\"", 4095)+"\r" })
}
