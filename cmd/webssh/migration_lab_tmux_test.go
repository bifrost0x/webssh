//go:build lab

package main

import (
	"encoding/binary"
	json "encoding/json/v2"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

// MG1-3 rest (W4-1): a persistent tmux terminal the Python release left
// on ssh-modern survives the migration. Go offers the migrated session
// and terminal.open reattaches the same tmux session with the shell state
// Python left in it; closing the tab ends tmux.
//
//	WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json go test -tags lab -run TestLabMigratedTmuxReattach ./cmd/webssh
func TestLabMigratedTmuxReattach(t *testing.T) {
	labJSON := os.Getenv("WEBSSH_LAB_JSON")
	if labJSON == "" {
		labJSON = filepath.Join(repoRoot, "tests", "lab", "runtime", "lab.json")
	}
	labJSON, err := filepath.Abs(labJSON)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(labJSON); err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	python, err := filepath.Abs(pythonPath())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "data")
	cmd := exec.CommandContext(t.Context(), python, "-m", "tests.golden.lab_variant", "--out", dir, "--lab", labJSON, "--tmux")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), helperTempDir(t)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Python lab data: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var facts struct {
		UserID   int64             `json:"user_id"`
		Profiles map[string]string `json:"profiles"`
		Tmux     string            `json:"tmux"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &facts); err != nil || facts.Tmux == "" {
		t.Fatalf("facts: %v\n%s", err, out)
	}

	env := map[string]string{
		"DATA_DIR": dir, "SESSION_COOKIE_SECURE": "false", "TMPDIR": t.TempDir(), "BACKUP_TEMP_DIR": t.TempDir(),
		"BLOCK_INTERNAL_SSH": "false", "TMUX_ENABLED": "true",
	}
	sys, err := openSystem(t.Context(), bootInput{lookup: lookupMap(env), log: slog.New(slog.DiscardHandler),
		stopping: func() bool { return false }, fastHashing: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sys.close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if !sys.startup.Migrated {
		t.Fatalf("the first start did not migrate: %+v", sys.startup)
	}
	owner := principaltest.User(facts.UserID)
	offer, err := sys.terminal.Persistent(t.Context(), owner)
	if err != nil || len(offer) != 1 || offer[0].TmuxSessionName != facts.Tmux || offer[0].DisplayName != "Lab tmux" {
		t.Fatalf("offer after the migration: %+v, %v", offer, err)
	}

	peer := protocoltest.NewPeer(t, owner)
	routes := map[string]protocol.Route{}
	for _, r := range sys.terminal.Routes() {
		routes[r.Type] = r
	}
	raw, perr := protocoltest.Call(t.Context(), routes[protocol.TypeTerminalOpen], peer, protocol.TerminalOpen{
		Ch: 1, RequestID: "mg13", Rows: 30, Cols: 100,
		Target: protocol.OpenTarget{ProfileID: facts.Profiles["direct"], AuthType: protocol.AuthPassword,
			UseTmux: true, TmuxSessionName: facts.Tmux}})
	if perr != nil {
		t.Fatalf("terminal.open: %+v", perr)
	}
	var opened protocol.TerminalOpened
	if err := json.Unmarshal(raw, &opened); err != nil {
		t.Fatal(err)
	}
	if !opened.Info.UseTmux || opened.Info.TmuxSessionName != facts.Tmux || opened.Info.DisplayName != "Lab tmux" {
		t.Fatalf("reattach: %+v", opened.Info)
	}
	if err := sys.terminal.HandleBinary(peer, protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindInput, Channel: 1, Seq: 1,
		Data: []byte("echo M=$MG13MARK\r")})); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		var screen strings.Builder
		var last uint64
		for _, b := range peer.Frames() {
			// Output frames: kind, flags, channel (4), sequence (8), data.
			if len(b) >= protocol.HeaderLen && protocol.Kind(b[0]) == protocol.KindOutput && binary.BigEndian.Uint32(b[2:6]) == 1 {
				screen.Write(b[protocol.HeaderLen:])
				last = binary.BigEndian.Uint64(b[6:14])
			}
		}
		if strings.Contains(screen.String(), "M=from-python") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the shell state of the Python session is gone: %q", screen.String())
		}
		_ = sys.terminal.HandleBinary(peer, protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindAck, Channel: 1, Seq: last}))
		time.Sleep(50 * time.Millisecond)
	}
	if _, perr := protocoltest.Call(t.Context(), routes[protocol.TypeTerminalClose], peer, protocol.SessionRef{SessionID: opened.SessionID}); perr != nil {
		t.Fatalf("close: %+v", perr)
	}
}
