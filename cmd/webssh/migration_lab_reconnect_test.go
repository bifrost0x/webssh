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

// MG1-3 (W4-1): after the migration a saved host of the Python release
// connects again through terminal.open as the page opens it, with the
// migrated saved password and with the migrated key, and its shell runs a
// command.
//
//	WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json go test -tags lab -run TestLabMigratedProfileReconnect ./cmd/webssh
func TestLabMigratedProfileReconnect(t *testing.T) {
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
	cmd := exec.CommandContext(t.Context(), python, "-m", "tests.golden.lab_variant", "--out", dir, "--lab", labJSON)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), helperTempDir(t)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Python lab data: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var facts labVariant
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &facts); err != nil {
		t.Fatalf("facts: %v\n%s", err, out)
	}

	env := map[string]string{
		"DATA_DIR": dir, "SESSION_COOKIE_SECURE": "false", "TMPDIR": t.TempDir(), "BACKUP_TEMP_DIR": t.TempDir(),
		"BLOCK_INTERNAL_SSH": "false", "PROXY_JUMP_REMOTE_DNS_ALLOWLIST": "ssh-inner.lab.test",
		"SOCKS_REMOTE_DNS_ALLOWLIST": "ssh-inner.lab.test",
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
	// Saved passwords are only handed out over HTTPS (connection_password).
	owner := principaltest.User(facts.UserID)
	owner.Secure = true
	routes := map[string]protocol.Route{}
	for _, r := range sys.terminal.Routes() {
		routes[r.Type] = r
	}

	// What realtime-terminal.js sends for a saved host: the profile, its
	// auth type and, for a saved password picked in the connection form
	// (credential_id), saved_password. Neither carries a secret.
	for _, tc := range []struct {
		name, profile, user string
		target              protocol.OpenTarget
	}{
		{name: "saved password", profile: "direct", user: "pwuser",
			target: protocol.OpenTarget{AuthType: protocol.AuthPassword, SavedPassword: true}},
		{name: "key via jump host", profile: "jump", user: "keyuser",
			target: protocol.OpenTarget{AuthType: protocol.AuthKey}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := protocoltest.NewPeer(t, owner)
			tc.target.ProfileID = facts.Profiles[tc.profile]
			raw, perr := protocoltest.Call(t.Context(), routes[protocol.TypeTerminalOpen], peer, protocol.TerminalOpen{
				Ch: 1, RequestID: "mg13-" + tc.profile, Rows: 30, Cols: 100, Target: tc.target})
			if perr != nil {
				t.Fatalf("terminal.open: %+v", perr)
			}
			var opened protocol.TerminalOpened
			if err := json.Unmarshal(raw, &opened); err != nil {
				t.Fatal(err)
			}
			// The marker is computed by the shell, so the echoed input
			// does not match it.
			if err := sys.terminal.HandleBinary(peer, protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindInput,
				Channel: 1, Seq: 1, Data: []byte("echo MG13-$((40+2))-$(id -un)\r")})); err != nil {
				t.Fatal(err)
			}
			want := "MG13-42-" + tc.user
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
				if strings.Contains(screen.String(), want) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no %q from the shell: %q", want, screen.String())
				}
				_ = sys.terminal.HandleBinary(peer, protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindAck, Channel: 1, Seq: last}))
				time.Sleep(50 * time.Millisecond)
			}
			if _, perr := protocoltest.Call(t.Context(), routes[protocol.TypeTerminalClose], peer, protocol.SessionRef{SessionID: opened.SessionID}); perr != nil {
				t.Fatalf("close: %+v", perr)
			}
		})
	}
}
