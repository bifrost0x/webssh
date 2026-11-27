//go:build lab

package main

import (
	"context"
	json "encoding/json/v2"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

type labService struct {
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Fingerprints map[string]string `json:"host_key_fingerprints"`
}

type labSSH struct {
	RuntimeDir string                `json:"runtime_dir"`
	Services   map[string]labService `json:"services"`
}

func readLab(t *testing.T) labSSH {
	t.Helper()
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		t.Fatal("set WEBSSH_LAB_JSON to the lab inventory")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var l labSSH
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

// labTerminalOpen runs terminal.open on sys for p and accepts the host
// keys the lab published for svc.
func labTerminalOpen(t *testing.T, sys *system, p principal.Principal, svc labService, target protocol.OpenTarget) protocol.TerminalOpened {
	t.Helper()
	routes := map[string]protocol.Route{}
	for _, r := range sys.terminal.Routes() {
		routes[r.Type] = r
	}
	ctx := principal.With(t.Context(), p)
	peer := protocoltest.NewPeer(t, p)
	type outcome struct {
		raw  []byte
		werr *protocol.Error
	}
	done := make(chan outcome, 1)
	go func() {
		raw, werr := protocoltest.Call(ctx, routes[protocol.TypeTerminalOpen], peer,
			protocol.TerminalOpen{Ch: 1, RequestID: "lab-fs", Rows: 24, Cols: 80, Target: target})
		done <- outcome{raw, werr}
	}()
	known := slices.Collect(maps.Values(svc.Fingerprints))
	answered := map[string]bool{}
	var res outcome
	for waiting := true; waiting; {
		select {
		case res = <-done:
			waiting = false
		case <-time.After(20 * time.Millisecond):
		}
		for _, ev := range peer.Events(protocol.TypePromptHostKey) {
			var q protocol.PromptHostKey
			if err := json.Unmarshal(ev.Payload, &q); err != nil {
				t.Fatal(err)
			}
			if answered[q.PromptID] {
				continue
			}
			answered[q.PromptID] = true
			if _, werr := protocoltest.Call(ctx, routes[protocol.TypePromptAnswer], peer,
				protocol.PromptAnswer{PromptID: q.PromptID, Kind: "host_key", Accepted: slices.Contains(known, q.Fingerprint)}); werr != nil {
				t.Fatalf("answer: %+v", werr)
			}
		}
	}
	if res.werr != nil {
		t.Fatalf("open: %+v", res.werr)
	}
	var opened protocol.TerminalOpened
	if err := json.Unmarshal(res.raw, &opened); err != nil {
		t.Fatal(err)
	}
	return opened
}

func labPassword(t *testing.T, l labSSH) string {
	t.Helper()
	pw, err := os.ReadFile(filepath.Join(l.RuntimeDir, "secrets", "ssh-pwuser"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(pw))
}

// checkSessionSource checks the file_source of a terminal session and
// opens it as the embedded file panel does.
func checkSessionSource(t *testing.T, sys *system, p principal.Principal, info protocol.SessionInfo, label string) {
	t.Helper()
	fs := info.FileSource
	if fs == nil || fs.SourceID != "sftp-session:"+info.SessionID || fs.Label != label || fs.Kind != "sftp" ||
		fs.Ephemeral || !fs.Security["host_key_verified"] || !slices.Contains(fs.Capabilities, "list") {
		t.Fatalf("file_source of %s: %+v", info.SessionID, fs)
	}
	listHome(principal.With(t.Context(), p), t, sys.fileSources, p, fs.SourceID)
}

// A real terminal session on ssh-modern names its file source in the
// terminal.open result; the embedded file panel opens exactly that source
// over the session's connection. After a reload (hello.restorable) the
// same source is named again and still lists the home directory.
func TestLabTerminalFileSourceOpensAfterRestore(t *testing.T) {
	l := readLab(t)
	modern := l.Services["ssh-modern"]
	sys, _ := openTestSystem(t, nil)
	p := principaltest.User(1)
	opened := labTerminalOpen(t, sys, p, modern, protocol.OpenTarget{Host: modern.Host, Port: modern.Port,
		Username: "pwuser", AuthType: "password", Password: labPassword(t, l)})
	checkSessionSource(t, sys, p, opened.Info, "pwuser@"+modern.Host)

	list, err := sys.terminal.Restorable(t.Context(), p)
	if err != nil || len(list) != 1 || list[0].SessionID != opened.SessionID {
		t.Fatalf("restorable %+v %v", list, err)
	}
	checkSessionSource(t, sys, p, list[0], "pwuser@"+modern.Host)
	other := principaltest.User(2)
	if _, _, err := sys.fileSources.Resolve(principal.With(t.Context(), other), other, list[0].FileSource.SourceID, files.CapList); err == nil {
		t.Fatal("another user opened the session's source")
	}
	if list, _ := sys.terminal.Restorable(t.Context(), other); len(list) != 0 {
		t.Fatalf("another user's restorable %+v", list)
	}
}

// After a server restart a persistent tmux session is offered without a
// file source (persistent_session_available had none); reattaching names
// the source of the new session, which opens over the new connection.
func TestLabTerminalFileSourceAfterRestartWithTmux(t *testing.T) {
	l := readLab(t)
	modern := l.Services["ssh-modern"]
	env := map[string]string{
		"DATA_DIR": filepath.Join(t.TempDir(), "data"), "SECRET_KEY": "system-test-secret-0123456789abcdef",
		"SESSION_COOKIE_SECURE": "false", "BOOTSTRAP_REGISTRATION_ENABLED": "true", "TMPDIR": t.TempDir(),
		"TMUX_ENABLED": "true",
	}
	start := func() *system {
		sys, err := openSystem(t.Context(), bootInput{lookup: lookupMap(env), log: slog.New(slog.DiscardHandler),
			stopping: func() bool { return false }, fastHashing: true})
		if err != nil {
			t.Fatal(err)
		}
		return sys
	}
	p := principaltest.User(1)
	target := protocol.OpenTarget{Host: modern.Host, Port: modern.Port, Username: "pwuser", AuthType: "password",
		Password: labPassword(t, l), UseTmux: true, DisplayName: "lab files"}

	first := start()
	opened := labTerminalOpen(t, first, p, modern, target)
	name := opened.Info.TmuxSessionName
	if !opened.Info.UseTmux || name == "" {
		t.Fatalf("no tmux on ssh-modern: %+v", opened.Info)
	}
	checkSessionSource(t, first, p, opened.Info, "lab files")
	if err := first.close(); err != nil {
		t.Fatal(err)
	}

	second := start()
	t.Cleanup(func() {
		if err := second.close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	offer, err := second.terminal.Persistent(t.Context(), p)
	if err != nil || len(offer) != 1 || offer[0].TmuxSessionName != name || offer[0].FileSource != nil {
		t.Fatalf("offer %+v %v", offer, err)
	}
	if list, _ := second.terminal.Restorable(t.Context(), p); len(list) != 0 {
		t.Fatalf("restorable after restart %+v", list)
	}
	target.TmuxSessionName = name
	again := labTerminalOpen(t, second, p, modern, target)
	if again.Info.TmuxSessionName != name {
		t.Fatalf("reattach %+v", again.Info)
	}
	checkSessionSource(t, second, p, again.Info, "lab files")
	// Closing the tab ends tmux on the host.
	routes := map[string]protocol.Route{}
	for _, r := range second.terminal.Routes() {
		routes[r.Type] = r
	}
	if _, werr := protocoltest.Call(principal.With(t.Context(), p), routes[protocol.TypeTerminalClose],
		protocoltest.NewPeer(t, p), protocol.SessionRef{SessionID: again.SessionID}); werr != nil {
		t.Fatalf("close: %+v", werr)
	}
}

// listHome opens sourceID as the file panel does (files.home, files.list)
// and reads the first entries of the login directory.
func listHome(ctx context.Context, t *testing.T, reg *files.Registry, p principal.Principal, sourceID string) {
	t.Helper()
	b, release, err := reg.Resolve(ctx, p, sourceID, files.CapList)
	if err != nil {
		t.Fatalf("resolve %s: %v", sourceID, err)
	}
	defer release()
	home, err := b.Home(ctx)
	if err != nil || home == "" {
		t.Fatalf("home %q %v", home, err)
	}
	ls, err := b.OpenListing(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	defer ls.Close()
	if _, _, err := ls.Next(ctx, 10); err != nil {
		t.Fatal(err)
	}
}
