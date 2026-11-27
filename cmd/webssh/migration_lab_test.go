//go:build lab

// The lab test of the migration (MG1-3): the Python release writes a data
// directory whose connections point at the shared test lab
// (tests/golden/lab_variant.py), Go migrates it at the first start and
// then connects over the migrated records with the server's own wiring:
//
//	WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json go test -tags lab -run TestLabMigrated ./cmd/webssh
//
// It fails, not skips, when the lab or the Python environment is missing.
package main

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
)

type labVariant struct {
	UserID     int64             `json:"user_id"`
	Profiles   map[string]string `json:"profiles"`
	ScheduleID string            `json:"schedule_id"`
}

// refuseHostKey answers no to every prompt: the migrated known_hosts must
// already trust every host on the route.
type refuseHostKey struct{}

func (refuseHostKey) HostKey(context.Context, client.HostKeyPrompt) (bool, error) { return false, nil }
func (refuseHostKey) Banner(context.Context, client.BannerPrompt) (bool, error)   { return true, nil }

func TestLabMigratedConnections(t *testing.T) {
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
	ctx := t.Context()

	// SOCKS5 (E21) with a migrated key (E23) and the migrated known_hosts
	// (E24): the saved host is resolved as the terminal resolves it.
	target, err := sys.hosts.Resolve(ctx, facts.UserID, facts.Profiles["socks"])
	if err != nil {
		t.Fatal(err)
	}
	target.Owner = facts.UserID
	conn, err := sys.shells.Dial(ctx, target, refuseHostKey{})
	if err != nil {
		t.Fatalf("SOCKS5 profile: %v", err)
	}
	var stdout bytes.Buffer
	if code, err := conn.Exec(ctx, "id -un", nil, &stdout, &bytes.Buffer{}); err != nil || code != 0 || stdout.String() != "keyuser\n" {
		t.Errorf("SOCKS5 profile: exit %d, %q, %v", code, stdout.String(), err)
	}
	_ = conn.Close()

	// The approved schedule (E15) keeps its approval and runs at once over
	// the saved password (E32) and the jump host (E20) without a new
	// review.
	var approved int
	if err := sys.db.Write(ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE automation_schedules SET next_at = ? WHERE id = ? AND enabled = 1`,
			time.Now().Unix(), facts.ScheduleID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		approved = int(n)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if approved != 1 {
		t.Fatalf("the migrated schedule is not active")
	}
	if err := sys.schedules.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	run := scheduledRun(t, sys.automation, facts.UserID, facts.ScheduleID)
	if run.Status != automation.StatusSucceeded || len(run.Targets) != 2 {
		t.Fatalf("scheduled run: %+v", run)
	}
	want := map[string]string{facts.Profiles["direct"]: "pwuser\n", facts.Profiles["jump"]: "keyuser\n"}
	for _, tg := range run.Targets {
		if len(tg.Steps) != 1 || tg.Steps[0].Status != automation.StatusSucceeded || tg.Steps[0].Stdout != want[tg.ID] {
			t.Errorf("target %s (%s): %+v", tg.Name, tg.ID, tg.Steps)
		}
	}
}

// scheduledRun waits for the run the schedule started to finish.
func scheduledRun(t *testing.T, svc *automation.Service, owner int64, scheduleID string) automation.Run {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		runs, err := svc.History(t.Context(), owner)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range runs {
			if r.ScheduleID != nil && *r.ScheduleID == scheduleID && r.Finished {
				return r
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the scheduled run did not finish")
	return automation.Run{}
}
