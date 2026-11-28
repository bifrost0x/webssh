package hostops

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The runtime inventory script against a host with four containers and
// three services, the first of each listed first. An awk array indexed
// by an unset variable stores the first row under "" instead of 0, so the
// END loop lost it and reported "Showing 3 of 4".

const (
	fakeDocker = `#!/bin/sh
case "$*" in
  "version --format {{.Server.Version}}") echo 27.3.1 ;;
  "ps -q") printf 'a\nb\nc\n' ;;
  "ps -aq") printf 'a\nb\nc\nd\n' ;;
  "ps -a --format {{.Names}}|{{.Status}}")
    printf '%s\n' 'app|Up 2 days (healthy)' 'web|Up 3 hours' 'db|Exited (0) 2 days ago' 'cache|Up 5 minutes' ;;
  *) exit 1 ;;
esac
`
	fakeSystemctl = `#!/bin/sh
case "$1" in
  show) echo running ;;
  list-units)
    printf '%s\n' 'cron.service loaded active running Regular background program processing daemon' \
      'ssh.service loaded active running OpenBSD Secure Shell server' \
      'backup.service loaded failed failed Nightly backup' ;;
  *) exit 1 ;;
esac
`
	wantDockerRows = "docker_returned=4\n" +
		"docker_container=app|Up 2 days (healthy)\n" +
		"docker_container=web|Up 3 hours\n" +
		"docker_container=db|Exited (0) 2 days ago\n" +
		"docker_container=cache|Up 5 minutes\n"
	wantSystemdRows = "systemd_returned=3\n" +
		"systemd_service=cron.service|loaded|active|running|Regular background program processing daemon\n" +
		"systemd_service=ssh.service|loaded|active|running|OpenBSD Secure Shell server\n" +
		"systemd_service=backup.service|loaded|failed|failed|Nightly backup\n"
)

// fakeHostBin writes the fake docker and systemctl, and awk as a link to
// the awk under test when one is given.
func fakeHostBin(t *testing.T, awk string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"docker": fakeDocker, "systemctl": fakeSystemctl} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if awk != "" {
		if err := os.Symlink(awk, filepath.Join(dir, "awk")); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// hostAwks are the awk implementations installed here, by name.
func hostAwks(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, name := range []string{"gawk", "mawk", "busybox", "original-awk", "nawk"} {
		if p, err := exec.LookPath(name); err == nil {
			found[name] = p
		}
	}
	if len(found) == 0 {
		t.Fatal("no awk implementation found")
	}
	return found
}

// checkFullInventory asserts that out of the whole script holds every
// row and parses to complete, untruncated sections.
func checkFullInventory(t *testing.T, out string) {
	t.Helper()
	for _, want := range []string{"docker_total=4\n" + "docker_running=3\n" + wantDockerRows, wantSystemdRows} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks\n%s\ngot\n%s", want, out)
		}
	}
	inv, err := ParseInventory(out)
	if err != nil {
		t.Fatal(err)
	}
	if d := inv.Docker; d == nil || d.Returned != 4 || d.Truncated || len(d.Containers) != 4 || d.Containers[0].Name != "app" {
		t.Errorf("docker %+v", inv.Docker)
	}
	if s := inv.Systemd; s == nil || s.Returned != 3 || s.Truncated || len(s.Services) != 3 || s.Services[0].Unit != "cron.service" {
		t.Errorf("systemd %+v", inv.Systemd)
	}
}

// captureFunction is capture_inventory_stdout of the embedded script.
func captureFunction(t *testing.T) string {
	t.Helper()
	start := strings.Index(inventoryProgram, "capture_inventory_stdout() {\n")
	if start < 0 {
		t.Fatal("capture_inventory_stdout not found")
	}
	end := strings.Index(inventoryProgram[start:], "\n}\n")
	if end < 0 {
		t.Fatal("capture_inventory_stdout not closed")
	}
	return inventoryProgram[start : start+end+3]
}

// The awk programs of the script keep the first row with every awk here,
// without namespaces or containers.
func TestInventoryAwkKeepsTheFirstRow(t *testing.T) {
	fn := captureFunction(t)
	for name, awk := range hostAwks(t) {
		bin := fakeHostBin(t, awk)
		for _, tc := range []struct{ kind, cmd, want string }{
			{"docker_containers", "docker ps -a --format '{{.Names}}|{{.Status}}'", wantDockerRows},
			{"systemd_units", "systemctl list-units", "systemd_total=3\nsystemd_active=2\nsystemd_failed=1\n" + wantSystemdRows},
		} {
			cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", fn+tc.cmd+" | capture_inventory_stdout "+tc.kind)
			cmd.Env = []string{"PATH=" + bin, "LC_ALL=C"}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s %s: %v %s", name, tc.kind, err, out)
			}
			if string(out) != tc.want {
				t.Errorf("%s %s:\n%s\nwant\n%s", name, tc.kind, out, tc.want)
			}
		}
	}
}

// The whole script, unchanged, with every awk here: bwrap puts the fakes
// into /usr/local/bin, which leads the PATH the script sets, and makes
// /run/systemd/system exist.
func TestInventoryScriptKeepsTheFirstRow(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap is not installed; the container test covers the whole script")
	}
	for name, awk := range hostAwks(t) {
		bin := fakeHostBin(t, awk)
		cmd := exec.CommandContext(t.Context(), bwrap, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
			"--tmpfs", "/tmp", "--tmpfs", "/run", "--dir", "/run/systemd/system",
			"--ro-bind", bin, "/usr/local/bin", "--", "/bin/sh", "-s")
		cmd.Stdin = strings.NewReader(inventoryProgram)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			if strings.Contains(stderr.String(), "bwrap:") {
				t.Skipf("bwrap cannot run here: %s", stderr.String())
			}
			t.Fatalf("%s: %v %s", name, err, stderr.String())
		}
		t.Run(name, func(t *testing.T) { checkFullInventory(t, string(out)) })
	}
}
