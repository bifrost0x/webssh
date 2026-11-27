package terminal

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type storeTx = store.Tx

func principalOf(id int64) principal.Principal { return principal.Principal{UserID: id} }

// fakeHost is a connection with tmux behaviour chosen by the test.
type fakeHost struct {
	mu         sync.Mutex
	lines      []string // commands run
	started    []string // command shells; "" is the login shell
	probe      int
	has        int
	hasErr     error
	kill       int
	killStderr string
	pty        *fakeShell
	closed     int
	noHerdr    bool // the Herdr lookup fails
}

func (h *fakeHost) run(_ context.Context, line string, _ time.Duration) (int, []byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, line)
	switch {
	case line == tmuxProbeCommand:
		return h.probe, nil, nil
	case line == herdrAvailableCommand:
		if h.noHerdr {
			return 1, nil, nil
		}
		return 0, nil, nil
	case strings.Contains(line, "has-session"):
		return h.has, nil, h.hasErr
	case strings.Contains(line, "kill-session"):
		return h.kill, []byte(h.killStderr), nil
	}
	return 127, nil, nil
}

func (h *fakeHost) open(line string) (client.Shell, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.started = append(h.started, line)
	h.pty = newFakeShell()
	return h.pty, nil
}

func (h *fakeHost) commandShell(_ context.Context, line string, _, _ int) (client.Shell, error) {
	return h.open(line)
}

func (h *fakeHost) shell(context.Context, int, int) (client.Shell, error) { return h.open("") }

func (h *fakeHost) sshConn() *client.Conn { return nil }

func (h *fakeHost) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed++
	return nil
}

func (h *fakeHost) ran() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

func (h *fakeHost) ranAny(part string) bool {
	for _, l := range h.ran() {
		if strings.Contains(l, part) {
			return true
		}
	}
	return false
}

type tmuxRig struct {
	m       *Manager
	shells  *fakeShells
	enabled atomic.Bool
	mu      sync.Mutex
	hosts   []*fakeHost
	next    func() *fakeHost
}

func newTmuxRig(t *testing.T) *tmuxRig {
	t.Helper()
	r := &tmuxRig{shells: &fakeShells{}, next: func() *fakeHost { return &fakeHost{} }}
	r.enabled.Store(true)
	m, err := New(Config{TmuxPrefix: "webssh"}, Deps{
		Quotas: testQuotas(t, 10, 5),
		Shells: r.shells, Log: slog.New(slog.DiscardHandler),
		DB: storetest.Open(t, Schema()), TmuxEnabled: func(context.Context) bool { return r.enabled.Load() },
	})
	if err != nil {
		t.Fatal(err)
	}
	m.dialHost = func(context.Context, client.Target, client.Interaction) (remoteHost, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		h := r.next()
		r.hosts = append(r.hosts, h)
		return h, nil
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
	})
	r.m = m
	return r
}

func (r *tmuxRig) host(t *testing.T, i int) *fakeHost {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.hosts) {
		t.Fatalf("host %d not dialled", i)
	}
	return r.hosts[i]
}

func (r *tmuxRig) rows(t *testing.T, owner int64) []PersistentRow {
	t.Helper()
	rows, err := r.m.store.ofUser(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func (r *tmuxRig) seed(t *testing.T, rows ...PersistentRow) {
	t.Helper()
	err := r.m.store.db.Write(t.Context(), func(tx *storeTx) error { return ImportPersistent(t.Context(), tx, rows) })
	if err != nil {
		t.Fatal(err)
	}
}

func tmuxOpen(ch uint32, rid, name string) protocol.TerminalOpen {
	req := openReq(ch, rid)
	req.Target.UseTmux, req.Target.TmuxSessionName = true, name
	return req
}

func detachedRow(id, name string) PersistentRow {
	return PersistentRow{SessionID: id, UserID: 1, Host: "h.example", Port: 22, Username: "u", AuthType: "password",
		TmuxSessionName: name, DisplayName: sql.NullString{String: "Build", Valid: true}, ReconnectRouteKnown: true,
		CreatedAt: sql.NullString{String: "2026-11-20 08:00:00.000000", Valid: true}}
}

func openTmux(t *testing.T, r *tmuxRig, peer protocol.Peer, req protocol.TerminalOpen) protocol.TerminalOpened {
	t.Helper()
	var res protocol.TerminalOpened
	if werr := call(t, r.m, peer, protocol.TypeTerminalOpen, req, &res); werr != nil {
		t.Fatalf("open: %+v", werr)
	}
	return res
}

func TestTmuxNewSessionIsStartedAndRecorded(t *testing.T) {
	r := newTmuxRig(t)
	res := openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", ""))
	name := res.Info.TmuxSessionName
	if !res.Info.UseTmux || !validTmuxName(name) || !strings.HasPrefix(name, "webssh_u_h_example_22_") || len(name) != len("webssh_u_h_example_22_")+8 {
		t.Fatalf("info %+v", res.Info)
	}
	h := r.host(t, 0)
	if got := h.ran(); len(got) != 1 || got[0] != "command -v tmux" {
		t.Fatalf("probe %q", got)
	}
	want := "tmux new-session -s '" + name + `' \; set-option -t '=` + name + ":' mouse on"
	if h.started[0] != want {
		t.Fatalf("started %q, want %q", h.started[0], want)
	}
	rows := r.rows(t, 1)
	if len(rows) != 1 || rows[0].SessionID != res.SessionID || rows[0].TmuxSessionName != name || !rows[0].Connected || rows[0].DisplayName.Valid {
		t.Fatalf("rows %+v", rows)
	}
	if list, _ := r.m.Persistent(t.Context(), principalOf(1)); len(list) != 0 {
		t.Fatalf("live session offered for reconnect: %+v", list)
	}
}

func TestTmuxMissingFallsBackToLoginShell(t *testing.T) {
	r := newTmuxRig(t)
	r.next = func() *fakeHost { return &fakeHost{probe: 1} }
	res := openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", ""))
	h := r.host(t, 0)
	if res.Info.UseTmux || res.Info.TmuxSessionName != "" || len(h.started) != 1 || h.started[0] != "" || len(r.rows(t, 1)) != 0 {
		t.Fatalf("fallback: %+v started %q", res.Info, h.started)
	}
	// The login shell owns the connection.
	call(t, r.m, user(t, 1), protocol.TypeTerminalClose, protocol.SessionRef{SessionID: res.SessionID}, nil)
	eventually(t, "connection closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
	if h.ranAny("kill-session") {
		t.Fatal("kill without tmux")
	}
}

func TestTmuxSwitchedOffUsesPlainShell(t *testing.T) {
	r := newTmuxRig(t)
	r.enabled.Store(false)
	res := openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", ""))
	if res.Info.UseTmux || len(r.hosts) != 1 || len(r.shells.opened) != 0 || r.host(t, 0).started[0] != "" || r.host(t, 0).ranAny("tmux") {
		t.Fatalf("tmux used while off: %+v", res.Info)
	}
	r.seed(t, detachedRow("old", "webssh_u_h_22_0a0b0c0d"))
	if list, _ := r.m.Persistent(t.Context(), principalOf(1)); len(list) != 0 {
		t.Fatal("reconnect offered while tmux is off")
	}
}

func TestTmuxReattachUsesStoredNameAndDisplayName(t *testing.T) {
	r := newTmuxRig(t)
	const name = "webssh_u_h_example_22_0a0b0c0d"
	r.seed(t, detachedRow("old", name))
	list, err := r.m.Persistent(t.Context(), principalOf(1))
	if err != nil || len(list) != 1 || list[0].TmuxSessionName != name || list[0].DisplayName != "Build" || list[0].SessionID != "old" {
		t.Fatalf("offer %+v %v", list, err)
	}
	res := openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", name))
	h := r.host(t, 0)
	if !strings.HasPrefix(h.started[0], "tmux new-session -A -s '"+name+"'") || res.Info.TmuxSessionName != name || res.Info.DisplayName != "Build" {
		t.Fatalf("reattach %q %+v", h.started, res.Info)
	}
	rows := r.rows(t, 1)
	if len(rows) != 1 || rows[0].SessionID != res.SessionID || rows[0].DisplayName.String != "Build" {
		t.Fatalf("old row not replaced: %+v", rows)
	}
}

func TestTmuxUnknownNameStartsNewSession(t *testing.T) {
	r := newTmuxRig(t)
	res := openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", "webssh_other_users_name"))
	if res.Info.TmuxSessionName == "webssh_other_users_name" || strings.Contains(r.host(t, 0).started[0], "-A") {
		t.Fatalf("unowned name attached: %+v", res.Info)
	}
	// Another user's row is not found either.
	r.seed(t, PersistentRow{SessionID: "x", UserID: 2, Host: "h", Port: 22, Username: "u", AuthType: "key", TmuxSessionName: "webssh_two"})
	res = openTmux(t, r, user(t, 1), tmuxOpen(2, "r2", "webssh_two"))
	if res.Info.TmuxSessionName == "webssh_two" {
		t.Fatal("attached to another user's tmux session")
	}
}

func TestTmuxRefusesInvalidNames(t *testing.T) {
	r := newTmuxRig(t)
	for i, name := range []string{"a;b", "a b", "x\n", "'x'", "ä", "a-b", strings.Repeat("a", 191)} {
		werr := call(t, r.m, user(t, 1), protocol.TypeTerminalOpen, tmuxOpen(uint32(i+1), "r", name), nil)
		if werr == nil || werr.Code != fault.InvalidValue || werr.Message != "Invalid tmux session name" {
			t.Fatalf("%q: %+v", name, werr)
		}
	}
	if len(r.hosts) != 0 {
		t.Fatal("dialled for an invalid name")
	}
}

func TestTmuxReattachKeepsSOCKSRoute(t *testing.T) {
	r := newTmuxRig(t)
	row := detachedRow("old", "webssh_via_proxy")
	row.SOCKSProxyID, row.ViaSOCKS = sql.NullString{String: "p1", Valid: true}, true
	r.seed(t, row)
	werr := call(t, r.m, user(t, 1), protocol.TypeTerminalOpen, tmuxOpen(1, "r", "webssh_via_proxy"), nil)
	if werr == nil || werr.Code != fault.InvalidValue || !strings.Contains(werr.Message, "different SOCKS5 route") {
		t.Fatalf("route change allowed: %+v", werr)
	}
	stray := detachedRow("old2", "webssh_flagged")
	stray.ViaSOCKS = true
	r.seed(t, stray)
	if werr := call(t, r.m, user(t, 1), protocol.TypeTerminalOpen, tmuxOpen(2, "r2", "webssh_flagged"), nil); werr == nil {
		t.Fatal("row through an unknown proxy reattached directly")
	}
	n, labels, err := r.m.UsingSOCKSProxy(t.Context(), 1, "p1")
	if err != nil || n != 1 || len(labels) != 1 || labels[0] != "Build" {
		t.Fatalf("usage %d %q %v", n, labels, err)
	}
	if n, _, _ := r.m.UsingSOCKSProxy(t.Context(), 2, "p1"); n != 0 {
		t.Fatal("other user's sessions counted")
	}
}

func TestTmuxCloseKillsSessionAndRow(t *testing.T) {
	r := newTmuxRig(t)
	peer := user(t, 1)
	res := openTmux(t, r, peer, tmuxOpen(1, "r1", ""))
	if werr := call(t, r.m, peer, protocol.TypeTerminalClose, protocol.SessionRef{SessionID: res.SessionID}, nil); werr != nil {
		t.Fatal(werr)
	}
	h := r.host(t, 0)
	eventually(t, "kill and close", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
	if !h.ranAny("tmux kill-session -t '=" + res.Info.TmuxSessionName + "'") {
		t.Fatalf("no exact kill: %q", h.ran())
	}
	if rows := r.rows(t, 1); len(rows) != 0 {
		t.Fatalf("row kept: %+v", rows)
	}
}

func TestTmuxCloseAfterReplacementKeepsTmux(t *testing.T) {
	r := newTmuxRig(t)
	const name = "webssh_u_h_example_22_0a0b0c0d"
	r.seed(t, detachedRow("old", name))
	peer := user(t, 1)
	first := openTmux(t, r, peer, tmuxOpen(1, "r1", name))
	// The tab reconnects: a second session attaches the same tmux session,
	// then the page closes the old one (preserve_tmux in the Python release).
	second := openTmux(t, r, peer, tmuxOpen(2, "r2", name))
	call(t, r.m, peer, protocol.TypeTerminalClose, protocol.SessionRef{SessionID: first.SessionID}, nil)
	h := r.host(t, 0)
	eventually(t, "old connection closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
	if h.ranAny("kill-session") {
		t.Fatal("tmux killed under the replacement")
	}
	rows := r.rows(t, 1)
	if len(rows) != 1 || rows[0].SessionID != second.SessionID {
		t.Fatalf("rows %+v", rows)
	}
}

func TestTmuxShellEndProbesTheHost(t *testing.T) {
	for _, tc := range []struct {
		name   string
		has    int
		hasErr error
		keeps  bool
	}{
		{"tmux still runs", 0, nil, true},
		{"tmux ended", 1, nil, false},
		{"cannot tell", 0, errors.New("channel closed"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTmuxRig(t)
			r.next = func() *fakeHost { return &fakeHost{has: tc.has, hasErr: tc.hasErr} }
			res := openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", ""))
			h := r.host(t, 0)
			_ = h.pty.Close() // the remote side ends the PTY channel
			eventually(t, "connection closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
			if !h.ranAny("tmux has-session -t '="+res.Info.TmuxSessionName+"'") || h.ranAny("kill-session") {
				t.Fatalf("commands %q", h.ran())
			}
			rows := r.rows(t, 1)
			if tc.keeps != (len(rows) == 1) || tc.keeps && rows[0].Connected {
				t.Fatalf("rows %+v", rows)
			}
			list, _ := r.m.Persistent(t.Context(), principalOf(1))
			if tc.keeps != (len(list) == 1) {
				t.Fatalf("offer %+v", list)
			}
		})
	}
}

func TestTmuxShutdownDetaches(t *testing.T) {
	r := newTmuxRig(t)
	openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", ""))
	if err := r.m.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := r.host(t, 0)
	if h.ranAny("kill-session") || h.closed != 1 {
		t.Fatalf("shutdown: %q closed=%d", h.ran(), h.closed)
	}
	if rows := r.rows(t, 1); len(rows) != 1 || rows[0].Connected {
		t.Fatalf("rows %+v", rows)
	}
}

func TestTmuxRevocation(t *testing.T) {
	for _, tc := range []struct {
		reason principal.Reason
		kills  bool
	}{
		{principal.ReasonLogout, false},
		{principal.ReasonPasswordChanged, true},
		{principal.ReasonAccountLocked, true},
	} {
		t.Run(string(tc.reason), func(t *testing.T) {
			r := newTmuxRig(t)
			r.seed(t, detachedRow("detached", "webssh_detached"))
			res := openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", ""))
			r.m.Revoked(principal.Revocation{SessionID: "b", UserID: 1, Reason: tc.reason})
			h := r.host(t, 0)
			eventually(t, "connection closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
			if h.ranAny("kill-session -t '="+res.Info.TmuxSessionName+"'") != tc.kills {
				t.Fatalf("kill=%v: %q", tc.kills, h.ran())
			}
			want := 2
			if tc.kills {
				want = 0
			}
			eventually(t, "rows settled", func() bool { return len(r.rows(t, 1)) == want })
		})
	}
}

func TestTmuxDiscardLateEndsNewSessionOnly(t *testing.T) {
	r := newTmuxRig(t)
	peer := user(t, 1)
	res := openTmux(t, r, peer, tmuxOpen(1, "r1", ""))
	call(t, r.m, peer, protocol.TypeTerminalDiscardLate, protocol.SessionRef{SessionID: res.SessionID, RequestID: "r1"}, nil)
	h := r.host(t, 0)
	eventually(t, "closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
	if !h.ranAny("kill-session") || len(r.rows(t, 1)) != 0 {
		t.Fatalf("new session kept: %q", h.ran())
	}
	r.seed(t, detachedRow("old", "webssh_keep_me"))
	res = openTmux(t, r, peer, tmuxOpen(2, "r2", "webssh_keep_me"))
	call(t, r.m, peer, protocol.TypeTerminalDiscardLate, protocol.SessionRef{SessionID: res.SessionID, RequestID: "r2"}, nil)
	h = r.host(t, 1)
	eventually(t, "closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
	if h.ranAny("kill-session") {
		t.Fatal("reattached tmux session killed")
	}
	if rows := r.rows(t, 1); len(rows) != 1 || rows[0].Connected {
		t.Fatalf("reattached row: %+v", rows)
	}
}

func TestTmuxRenamePersists(t *testing.T) {
	r := newTmuxRig(t)
	peer := user(t, 1)
	res := openTmux(t, r, peer, tmuxOpen(1, "r1", ""))
	if werr := call(t, r.m, peer, protocol.TypeTerminalRename, protocol.TerminalRename{SessionID: res.SessionID, Name: "  Deploy  "}, nil); werr != nil {
		t.Fatal(werr)
	}
	if rows := r.rows(t, 1); rows[0].DisplayName.String != "Deploy" {
		t.Fatalf("live rename: %+v", rows[0])
	}
	r.seed(t, detachedRow("old", "webssh_old"))
	if werr := call(t, r.m, peer, protocol.TypeTerminalRename, protocol.TerminalRename{SessionID: "old", Name: ""}, nil); werr != nil {
		t.Fatal(werr)
	}
	for _, row := range r.rows(t, 1) {
		if row.SessionID == "old" && row.DisplayName.Valid {
			t.Fatalf("cleared name stored: %+v", row)
		}
	}
	for _, rename := range []struct {
		peer *peerT
		id   string
	}{{peer, "missing"}, {user(t, 2), "old"}} {
		werr := call(t, r.m, rename.peer, protocol.TypeTerminalRename, protocol.TerminalRename{SessionID: rename.id, Name: "x"}, nil)
		if werr == nil || werr.Code != fault.NotFound {
			t.Fatalf("rename %q: %+v", rename.id, werr)
		}
	}
}

func TestNewTmuxNameFollowsTheScheme(t *testing.T) {
	cases := []struct{ prefix, user, host, want string }{
		{"webssh", "a.b-c", "10.0.0.1", "webssh_a_b_c_10_0_0_1_22_"},
		{"webssh", "u", "fe80::1", "webssh_u_fe80__1_22_"},
		{"", "u", "bücher.example", "webssh_u_b_cher_example_22_"},
		{"my-prefix", "u", "h", "my_prefix_u_h_22_"},
	}
	for _, c := range cases {
		got := newTmuxName(c.prefix, c.user, c.host, 22)
		if !strings.HasPrefix(got, c.want) || len(got) != len(c.want)+8 || !validTmuxName(got) {
			t.Fatalf("%+v: %q", c, got)
		}
	}
	long := newTmuxName(strings.Repeat("p", 80), strings.Repeat("u", 40), strings.Repeat("h", 253), 65535)
	if len(long) > maxTmuxName || !validTmuxName(long) || !strings.HasSuffix(long[:len(long)-8], "_65535_") {
		t.Fatalf("long name %q (%d)", long, len(long))
	}
	if a, b := newTmuxName("w", "u", "h", 22), newTmuxName("w", "u", "h", 22); a == b {
		t.Fatal("names are not random")
	}
}

func TestTmuxCommandsRefuseUncheckedNames(t *testing.T) {
	for _, name := range []string{"", "a'b", "a b"} {
		if _, err := tmuxAttachCommand("tmux", name, false); err == nil {
			t.Fatalf("attach %q", name)
		}
		if _, err := tmuxTargetCommand("kill-session", name); err == nil {
			t.Fatalf("kill %q", name)
		}
	}
}

func FuzzNewTmuxName(f *testing.F) {
	f.Add("webssh", "user", "host.example", 22)
	f.Add("", "", "", 0)
	f.Fuzz(func(t *testing.T, prefix, user, host string, port int) {
		port = port & 0xffff
		name := newTmuxName(prefix, user, host, port)
		if !validTmuxName(name) {
			t.Fatalf("invalid name %q", name)
		}
		if _, err := tmuxAttachCommand("tmux", name, true); err != nil {
			t.Fatalf("name %q not usable: %v", name, err)
		}
	})
}

func TestImportPersistentKeepsValuesAsRead(t *testing.T) {
	r := newTmuxRig(t)
	odd := "webssh_us\u00e9r@x_h_22_0a0b0c0d" // not reattachable, still kept and listed
	in := detachedRow("legacy-1", odd)
	in.Connected = true
	in.KeyID = sql.NullString{String: "k1", Valid: true}
	in.LastActivity = sql.NullString{String: "2026-11-21 09:30:00", Valid: true}
	second := detachedRow("legacy-2", "webssh_second")
	second.DisplayName = sql.NullString{}
	r.seed(t, in, second)
	rows := r.rows(t, 1)
	in.Connected = false
	if len(rows) != 2 || rows[0] != in || rows[1] != second {
		t.Fatalf("imported %+v", rows)
	}
	list, err := r.m.Persistent(t.Context(), principalOf(1))
	if err != nil || len(list) != 2 || list[0].TmuxSessionName != odd || list[1].DisplayName != "" {
		t.Fatalf("offer %+v %v", list, err)
	}
	werr := call(t, r.m, user(t, 1), protocol.TypeTerminalOpen, tmuxOpen(1, "r", odd), nil)
	if werr == nil || werr.Code != fault.InvalidValue {
		t.Fatalf("unsafe name reached a command: %+v", werr)
	}
	raw := detachedRow("legacy-3", "webssh_\xff\xfe_raw")
	raw.UserID = 3
	r.seed(t, raw)
	if got := r.rows(t, 3); len(got) != 1 || got[0].TmuxSessionName != "webssh_\xff\xfe_raw" {
		t.Fatalf("bytes changed: %+v", got)
	}
	err = r.m.store.db.Write(t.Context(), func(tx *storeTx) error {
		return ImportPersistent(t.Context(), tx, []PersistentRow{detachedRow("legacy-1", "dup")})
	})
	if err == nil {
		t.Fatal("duplicate session id imported")
	}
}
