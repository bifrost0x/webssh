//go:build lab

package terminal

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// The tmux lab test needs tmux on the target. ssh-modern of the lab has
// none yet; WEBSSH_LAB_TMUX_PORT names a local port of a container of the
// ssh-modern image with tmux added (same host key and users). Without it
// the test runs against ssh-modern and fails if tmux is missing there.
func labTmuxHop(t *testing.T, auth client.Auth) (client.Hop, bool) {
	t.Helper()
	hop := labHop(t, "ssh-modern", false, auth)
	port := os.Getenv("WEBSSH_LAB_TMUX_PORT")
	if port == "" {
		return hop, false
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("WEBSSH_LAB_TMUX_PORT: %v", err)
	}
	hop.Port = n
	return hop, true
}

func newLabTmuxManager(t *testing.T, profiles fakeProfiles) (*Manager, *client.Dialer) {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	policy, err := netpolicy.New(netpolicy.Config{Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	db := storetest.Open(t, hostkey.Schema(), Schema())
	dialer := &client.Dialer{Net: policy, HostKeys: hostkey.New(db, log)}
	m, err := New(Config{TmuxPrefix: "webssh"}, Deps{
		Shells: dialer, Connections: dialer, Profiles: profiles, Log: log,
		DB: db, TmuxEnabled: func(context.Context) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
	})
	return m, dialer
}

// hostTmux runs a tmux command on its own connection and returns the exit
// status and output.
func hostTmux(t *testing.T, d *client.Dialer, tg client.Target, line string) (int, string) {
	t.Helper()
	c, err := d.Dial(t.Context(), tg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	r, err := remotecmd.Run(t.Context(), c, remotecmd.Command{Line: line})
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	return r.ExitStatus, string(r.Stdout)
}

func labTmuxOpen(t *testing.T, m *Manager, peer *peerT, ch uint32, name string) protocol.TerminalOpened {
	t.Helper()
	res, _, werr := labOpenTarget(t, m, peer, protocol.TerminalOpen{Ch: ch, RequestID: "tmux-" + strconv.Itoa(int(ch)), Rows: 30, Cols: 100,
		Target: protocol.OpenTarget{ProfileID: "tmux", AuthType: "password", UseTmux: true, TmuxSessionName: name}})
	if werr != nil {
		t.Fatalf("open: %+v", werr)
	}
	return res
}

func TestLabTmux(t *testing.T) {
	pw := client.Auth{Password: labSecret(t, "secrets/ssh-pwuser")}
	hop, separate := labTmuxHop(t, pw)
	tg := client.Target{Owner: 1, Hop: hop}
	profiles := fakeProfiles{"tmux": tg, "modern": {Owner: 1, Hop: labHop(t, "ssh-modern", false, pw)}}
	m, dialer := newLabTmuxManager(t, profiles)

	// A new session runs in tmux, with mouse input on for exactly it.
	peer := user(t, 1)
	first := labTmuxOpen(t, m, peer, 1, "")
	name := first.Info.TmuxSessionName
	if !first.Info.UseTmux || !validTmuxName(name) {
		t.Fatalf("no tmux on %s:%d: %+v", hop.Host, hop.Port, first.Info)
	}
	labRun(t, m, peer, 1, 1, "export D6MARK=kept; echo T=$((6*7)) ${TMUX:+in-tmux}\r", "T=42 in-tmux")
	if st, _ := hostTmux(t, dialer, tg, "tmux has-session -t '="+name+"'"); st != 0 {
		t.Fatalf("has-session %d", st)
	}
	if _, out := hostTmux(t, dialer, tg, "tmux show-options -t '="+name+":' mouse"); !strings.Contains(out, "mouse on") {
		t.Fatalf("mouse option %q", out)
	}

	// Signing out detaches: tmux keeps running and the session is offered.
	m.Revoked(principal.Revocation{SessionID: "b", UserID: 1, Reason: principal.ReasonLogout})
	eventually(t, "detached", func() bool { return m.Stats().Sessions == 0 })
	var offer []protocol.SessionInfo
	deadline := time.Now().Add(10 * time.Second)
	for len(offer) != 1 && time.Now().Before(deadline) {
		offer, _ = m.Persistent(t.Context(), principalOf(1))
		time.Sleep(50 * time.Millisecond)
	}
	if len(offer) != 1 || offer[0].TmuxSessionName != name {
		t.Fatalf("offer %+v", offer)
	}
	if st, _ := hostTmux(t, dialer, tg, "tmux has-session -t '="+name+"'"); st != 0 {
		t.Fatal("sign-out ended tmux")
	}

	// Reattaching finds the same tmux session with its shell state.
	peer = user(t, 1)
	second := labTmuxOpen(t, m, peer, 2, name)
	if second.Info.TmuxSessionName != name {
		t.Fatalf("reattach %+v", second.Info)
	}
	labRun(t, m, peer, 2, 1, "echo M=$D6MARK\r", "M=kept")
	if call(t, m, peer, protocol.TypeTerminalRename, protocol.TerminalRename{SessionID: second.SessionID, Name: "Lab build"}, nil) != nil {
		t.Fatal("rename")
	}

	// Closing the tab ends tmux.
	if werr := call(t, m, peer, protocol.TypeTerminalClose, protocol.SessionRef{SessionID: second.SessionID}, nil); werr != nil {
		t.Fatal(werr)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		st, _ := hostTmux(t, dialer, tg, "tmux has-session -t '="+name+"'")
		if st != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tmux survived the close")
		}
		time.Sleep(100 * time.Millisecond)
	}
	eventually(t, "row removed", func() bool { rows, _ := m.store.ofUser(t.Context(), 1); return len(rows) == 0 })

	// Leaving tmux from inside ends the session and its row.
	third := labTmuxOpen(t, m, peer, 3, "")
	labRun(t, m, peer, 3, 1, "echo READY\r", "READY")
	if err := m.HandleBinary(peer, input(3, 2, "exit\r", false)); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for {
		rows, _ := m.store.ofUser(t.Context(), 1)
		if len(rows) == 0 && m.Stats().Sessions == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after exit: rows %+v stats %+v", rows, m.Stats())
		}
		var last uint64
		for _, f := range frames(t, peer) {
			if f.Kind == protocol.KindOutput && f.Channel == 3 {
				last = f.Seq
			}
		}
		_ = m.HandleBinary(peer, ack(3, last))
		time.Sleep(100 * time.Millisecond)
	}
	if st, _ := hostTmux(t, dialer, tg, "tmux has-session -t '="+third.Info.TmuxSessionName+"'"); st == 0 {
		t.Fatal("tmux still runs after exit")
	}

	// A host without tmux gets the login shell.
	if separate {
		res, _, werr := labOpenTarget(t, m, peer, protocol.TerminalOpen{Ch: 4, RequestID: "plain", Rows: 24, Cols: 80,
			Target: protocol.OpenTarget{ProfileID: "modern", AuthType: "password", UseTmux: true}})
		if werr != nil || res.Info.UseTmux {
			t.Fatalf("fallback: %+v %+v", werr, res.Info)
		}
		labRun(t, m, peer, 4, 1, "echo P=$((2+3)) ${TMUX:-plain}\r", "P=5 plain")
	}
}
