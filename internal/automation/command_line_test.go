package automation

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// lineExec records the exec line and the data sent on stdin.
type lineExec struct {
	line  string
	stdin []byte
	err   error
}

func (l *lineExec) Exec(_ context.Context, line string, stdin io.Reader, _, _ io.Writer) (int, error) {
	l.line = line
	if l.err != nil {
		return -1, l.err
	}
	if stdin != nil {
		l.stdin, _ = io.ReadAll(stdin)
	}
	return 0, nil
}

// A step reaches the host as the exec request Python sent: unchanged
// for the login shell, behind "sudo -n -- sh -c" with shlex quoting for
// sudo (command_for of app/automation_transport.py, recorded in
// testdata/command_line.json), and with nothing on stdin.
func TestStepCommandLineMatchesPython(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/command_line.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Command string `json:"command"`
		Sudo    bool   `json:"sudo"`
		Line    string `json:"line"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) < 50 {
		t.Fatalf("corpus: %d cases, %v", len(cases), err)
	}
	for i, c := range cases {
		cmd, err := remotecmd.Shell(c.Command, c.Sudo)
		if err != nil || cmd.Line != c.Line || cmd.Stdin != nil {
			t.Errorf("case %d (sudo %v): Shell = %q, %v; want %q", i, c.Sudo, cmd.Line, err, c.Line)
			continue
		}
		exec := &lineExec{}
		got := runStep(t.Context(), exec, Step{Name: "s", Command: c.Command, Timeout: 30, Sudo: c.Sudo},
			func() bool { return false }, nil, 1<<16, time.Now)
		if exec.line != c.Line || len(exec.stdin) != 0 || got.Status != StatusSucceeded {
			t.Errorf("case %d: runStep sent %q (stdin %d bytes), status %s", i, exec.line, len(exec.stdin), got.Status)
		}
	}
}

// An exec request that left WebSSH without a confirmed start may have
// run: the step is unknown, never dispatch_failed (execute_step of
// Python: acknowledgement_lost).
func TestUnconfirmedExecIsUnknown(t *testing.T) {
	t.Parallel()
	step := Step{Name: "s", Command: "reboot", Timeout: 30}
	never := func() bool { return false }
	sent := &lineExec{err: errors.Join(client.ErrExecUnconfirmed, errors.New("connection lost"))}
	if got := runStep(t.Context(), sent, step, never, nil, 1<<16, time.Now); got.Status != StatusUnknown || deref(got.Reason) != "acknowledgement_lost" {
		t.Fatalf("unconfirmed exec: %s %s", got.Status, deref(got.Reason))
	}
	refused := &lineExec{err: errors.New("channel open refused")}
	if got := runStep(t.Context(), refused, step, never, nil, 1<<16, time.Now); got.Status != StatusFailed || deref(got.Reason) != "dispatch_failed" {
		t.Fatalf("no channel: %s %s", got.Status, deref(got.Reason))
	}
	if _, err := remotecmd.Shell(strings.Repeat("x", remotecmd.MaxShellCommand+1), false); err == nil {
		t.Fatal("an oversized step command was accepted")
	}
}
