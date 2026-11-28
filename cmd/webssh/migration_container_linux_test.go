//go:build container && linux && !race

// W4-2: the first migration in the real image under the memory limit of
// the container. The image must be the debug target (it has cat for the
// cgroup files):
//
//	docker build --target debug -t webssh:local-debug .
//	WEBSSH_CONTAINER_IMAGE=webssh:local-debug go test -tags container -run TestContainerMigrationMemory -timeout 30m ./cmd/webssh
//
// DOCKER_CONTEXT selects the daemon (rootless in the lab). The data
// directory is bind-mounted, so the container runs as root, which a
// rootless daemon maps to the calling user.

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gcGoal is the heap goal of a GODEBUG=gctrace=1 line.
var gcGoal = regexp.MustCompile(`, (\d+) MB goal,`)

func docker(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "docker", args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// TestContainerMigrationMemory migrates a large golden data set at the
// first start of the image, once with mem_limit 512 MiB and once with
// 2 GiB. The start must reach /ready without an OOM kill, the peak
// resident set of the server stays below the limit, and the heap goal of the
// garbage collector stays below three quarters of the limit: GOMEMLIMIT
// was taken from the cgroup (applyMemoryLimit), not set by the test.
func TestContainerMigrationMemory(t *testing.T) {
	image := os.Getenv("WEBSSH_CONTAINER_IMAGE")
	if image == "" {
		t.Fatal("set WEBSSH_CONTAINER_IMAGE to the debug image")
	}
	for _, c := range []struct {
		name         string
		limit        int64
		users, store int
		gogc         string
	}{
		// Many accounts with medium stores: the limit of a small host.
		{"512MiB", 512 << 20, 20, 12 << 20, ""},
		// The same data with a garbage collector that would let the heap
		// grow to five times the live heap: only the soft limit from the
		// cgroup keeps the goal below 192 MiB.
		{"256MiB-GOGC400", 256 << 20, 20, 12 << 20, "400"},
		// The stores of the K10 memory test, just below the 64 MiB limit.
		{"2GiB", 2 << 30, 10, 63 << 20, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := extractGolden(t, "datadir-extended.tar")
			for i := range c.users {
				d := filepath.Join(dir, "users", fmt.Sprintf("user_%d", 3+i))
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
				bigStore(t, filepath.Join(d, "profiles.json"), "profiles", 3, 400, c.store)
				bigStore(t, filepath.Join(d, "jump_hosts.json"), "jump_hosts", 2, 100, c.store)
			}
			name := fmt.Sprintf("webssh-w42-%s-%d", strings.ToLower(c.name), time.Now().UnixNano())
			limit := strconv.FormatInt(c.limit, 10)
			args := []string{"run", "-d", "--name", name, "--memory", limit, "--memory-swap", limit,
				"--user", "0:0", "-e", "GODEBUG=gctrace=1", "-e", "SESSION_COOKIE_SECURE=false", "-v", dir + ":/app/data"}
			if c.gogc != "" {
				args = append(args, "-e", "GOGC="+c.gogc)
			}
			if out, err := docker(t, append(args, image, "serve", "--bind", "0.0.0.0:5000")...); err != nil {
				t.Fatalf("docker run: %v\n%s", err, out)
			}
			t.Cleanup(func() { _, _ = docker(t, "rm", "-f", name) })
			start := time.Now()
			deadline := start.Add(15 * time.Minute)
			for {
				state, err := docker(t, "inspect", "-f", "{{.State.Status}} {{.State.OOMKilled}} {{.State.ExitCode}}", name)
				if err != nil {
					t.Fatalf("inspect: %v %s", err, state)
				}
				if !strings.HasPrefix(state, "running ") {
					logs, _ := docker(t, "logs", "--tail", "40", name)
					t.Fatalf("container ended (%s):\n%s", state, logs)
				}
				if _, err := docker(t, "exec", name, "/app/webssh", "healthcheck"); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("no /ready within 15 minutes")
				}
				time.Sleep(2 * time.Second)
			}
			took := time.Since(start)
			// The cgroup's own peak counts the page cache of the data
			// directory as well and reaches the limit by design; what
			// counts is that nothing was OOM-killed and the peak resident
			// set of the server (PID 1) stays below the limit.
			events, err := docker(t, "exec", name, "cat", "/sys/fs/cgroup/memory.events")
			if err != nil {
				t.Fatalf("memory.events: %v %s", err, events)
			}
			if !strings.Contains(events, "oom_kill 0") {
				t.Fatalf("OOM kill in the container:\n%s", events)
			}
			status, err := docker(t, "exec", name, "cat", "/proc/1/status")
			if err != nil {
				t.Fatalf("status: %v %s", err, status)
			}
			var peak int64
			for line := range strings.Lines(status) {
				if rest, ok := strings.CutPrefix(line, "VmHWM:"); ok {
					kb, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "kB")), 10, 64)
					peak = kb << 10
				}
			}
			if peak == 0 {
				t.Fatalf("no VmHWM:\n%s", status)
			}
			logs, err := docker(t, "logs", name)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(logs, "migration completed") {
				t.Fatalf("no migration in the log:\n%s", logs)
			}
			maxGoal := int64(0)
			sc := bufio.NewScanner(strings.NewReader(logs))
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				if m := gcGoal.FindStringSubmatch(sc.Text()); m != nil {
					g, _ := strconv.ParseInt(m[1], 10, 64)
					maxGoal = max(maxGoal, g)
				}
			}
			soft := c.limit / 4 * 3 >> 20
			t.Logf("%d accounts x 2 stores of %d MiB: ready after %s, peak RSS %d MiB of %d MiB, highest heap goal %d MiB (soft limit %d MiB)",
				c.users, c.store>>20, took.Round(time.Second), peak>>20, c.limit>>20, maxGoal, soft)
			if maxGoal == 0 {
				t.Fatal("no gctrace output")
			}
			// gctrace prints the goal in MiB. With the soft limit the goal
			// never passes it (some slack for rounding).
			if maxGoal > soft*105/100 {
				t.Fatalf("heap goal %d MiB above the soft limit %d MiB: GOMEMLIMIT was not taken from the cgroup", maxGoal, soft)
			}
			if peak >= c.limit {
				t.Fatalf("peak RSS %d MiB at the limit", peak>>20)
			}
		})
	}
}
