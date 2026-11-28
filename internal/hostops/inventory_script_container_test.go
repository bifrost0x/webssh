//go:build container && linux

// The runtime inventory script, unchanged, with the awk of other
// distributions (mawk on Debian and Ubuntu, busybox awk on Alpine):
//
//	go test -tags container -run TestContainerInventory ./internal/hostops
//
// DOCKER_CONTEXT selects the daemon (rootless in the lab).
// WEBSSH_AWK_IMAGES overrides the images, separated by commas.
package hostops

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestContainerInventoryKeepsTheFirstRow(t *testing.T) {
	images := []string{"debian:stable-slim", "alpine:3"}
	if v := os.Getenv("WEBSSH_AWK_IMAGES"); v != "" {
		images = strings.Split(v, ",")
	}
	bin := fakeHostBin(t, "")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "docker", "run", "--rm", "-i", "--network", "none",
				"-v", bin+":/usr/local/bin:ro", image,
				"sh", "-c", "mkdir -p /run/systemd/system && readlink -f \"$(command -v awk)\" >&2 && exec sh -s")
			cmd.Stdin = strings.NewReader(inventoryProgram)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%v %s", err, stderr.String())
			}
			t.Logf("awk: %s", strings.TrimSpace(stderr.String()))
			checkFullInventory(t, string(out))
		})
	}
}
