//go:build lab

package client_test

import (
	"bufio"
	"context"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// A command that never ends on the host (a stuck Herdr snapshot, a hung
// collector) ends at its own deadline. Only its channel closes: the
// terminal on the same connection keeps working, and the next command
// runs (RC0-1).
func TestLabStuckCommandEndsOnlyItsChannel(t *testing.T) {
	r := newRig(t, netpolicy.Config{})
	tgt := client.Target{Owner: 1, Hop: hop(t, "ssh-modern", "pwuser", client.Auth{Password: secret(t, "secrets/ssh-pwuser")})}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	sh, err := r.dialer.OpenShell(ctx, tgt, r.ix, 24, 80)
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	defer func() { _ = sh.Close() }()
	conn := client.ConnOf(sh)
	if conn == nil {
		t.Fatal("the shell has no connection")
	}
	out := bufio.NewReader(sh)
	roundtrip := func(marker string) {
		t.Helper()
		if _, err := io.WriteString(sh, "echo "+marker+"-$((40+2))\n"); err != nil {
			t.Fatalf("terminal write: %v", err)
		}
		want := marker + "-42"
		deadline := time.AfterFunc(10*time.Second, func() { _ = sh.Close() })
		defer deadline.Stop()
		var seen strings.Builder
		for !strings.Contains(seen.String(), want) {
			line, err := out.ReadString('\n')
			seen.WriteString(line)
			if err != nil {
				t.Fatalf("terminal read: %v after %q", err, seen.String())
			}
		}
	}
	roundtrip("BEFORE")

	// The same deadline as the Herdr snapshot; sleep stands for a command
	// without its own guard on the host.
	// A value of its own per run, so the check below sees this command.
	stuck := "sleep " + strconv.Itoa(3000+int(time.Now().UnixNano()%997))
	start := time.Now()
	_, err = remotecmd.Run(ctx, conn, remotecmd.Command{Line: stuck, Timeout: 3 * time.Second})
	took := time.Since(start)
	if fault.CodeOf(err) != fault.Timeout {
		t.Fatalf("stuck command: %v, want timeout", err)
	}
	if took < 3*time.Second || took > 3500*time.Millisecond {
		t.Fatalf("stuck command answered after %v, want its 3 s deadline", took)
	}
	select {
	case <-conn.Done():
		t.Fatal("the deadline of one command closed the connection")
	default:
	}

	// Wait past the setup budget, after which the old code closed the
	// whole connection.
	time.Sleep(client.DefaultHandshakeTimeout + time.Second)
	roundtrip("AFTER")
	res, err := remotecmd.Run(ctx, conn, remotecmd.Command{Line: "pgrep -u pwuser -f '[s]" + stuck[1:] + "' || echo none"})
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "none" {
		t.Fatalf("the stuck command still runs on the host: %q %v", res.Stdout, err)
	}
}
