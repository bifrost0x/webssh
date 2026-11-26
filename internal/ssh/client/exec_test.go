package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// exec runs the commands of the exec tests on the test server.
func (s *testServer) exec(ch ssh.Channel, payload []byte) {
	defer func() { _ = ch.Close() }()
	if len(payload) < 4 {
		return
	}
	command := string(payload[4:])
	status := func(code uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], code)
		_, _ = ch.SendRequest("exit-status", false, b[:])
	}
	switch {
	case command == "cat":
		_, _ = io.Copy(ch, ch)
		status(0)
	case strings.HasPrefix(command, "exit "):
		_, _ = ch.Stderr().Write([]byte("failed"))
		n := uint32(command[len(command)-1] - '0')
		status(n)
	case command == "signal":
		_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
			Signal     string
			CoreDumped bool
			Msg, Lang  string
		}{Signal: "KILL"}))
	case command == "nostatus":
	case command == "hang":
		// Hold the channel open past the caller's deadline.
		time.Sleep(3 * time.Second)
	case command == "tty":
		_, _ = ch.Write([]byte("on a tty\r\n"))
		status(0)
	default:
		status(127)
	}
}

func dialExec(t *testing.T) *Conn {
	t.Helper()
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	d, _ := newDialer(trusting(s), nil)
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestExecStatusAndStreams(t *testing.T) {
	c := dialExec(t)
	var out bytes.Buffer
	code, err := c.Exec(t.Context(), "cat", strings.NewReader("data on stdin"), &out, nil)
	if err != nil || code != 0 || out.String() != "data on stdin" {
		t.Fatalf("cat: %d %v %q", code, err, out.String())
	}
	var errOut bytes.Buffer
	code, err = c.Exec(t.Context(), "exit 3", nil, nil, &errOut)
	if err != nil || code != 3 || errOut.String() != "failed" {
		t.Fatalf("exit 3: %d %v %q", code, err, errOut.String())
	}
	code, err = c.Exec(t.Context(), "unknown", nil, nil, nil)
	if err != nil || code != 127 {
		t.Fatalf("unknown: %d %v", code, err)
	}
}

func TestExecWithoutStatusIsUnknown(t *testing.T) {
	c := dialExec(t)
	for _, command := range []string{"signal", "nostatus"} {
		code, err := c.Exec(t.Context(), command, nil, nil, nil)
		if !errors.Is(err, ErrNoExitStatus) || code != -1 {
			t.Fatalf("%s: %d %v", command, code, err)
		}
	}
}

func TestExecEndsWithContext(t *testing.T) {
	c := dialExec(t)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Exec(ctx, "hang", strings.NewReader(""), nil, nil)
	if fault.CodeOf(err) != fault.Timeout || time.Since(start) > 2*time.Second {
		t.Fatalf("hang: %v after %v", err, time.Since(start))
	}
}

func TestExecRefusesInvalidCommands(t *testing.T) {
	c := dialExec(t)
	for _, command := range []string{"", "a\x00b", strings.Repeat("x", maxCommandLen+1)} {
		if _, err := c.Exec(t.Context(), command, nil, nil, nil); fault.CodeOf(err) != fault.InvalidValue {
			t.Fatalf("%q accepted: %v", command[:min(len(command), 8)], err)
		}
		if _, err := c.CommandShell(t.Context(), command, 24, 80); fault.CodeOf(err) != fault.InvalidValue {
			t.Fatalf("command shell %q accepted: %v", command[:min(len(command), 8)], err)
		}
	}
}

func TestCommandShellRunsWithPTY(t *testing.T) {
	c := dialExec(t)
	sh, err := c.CommandShell(t.Context(), "tty", 30, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(sh)
	if string(got) != "on a tty\r\n" {
		t.Fatalf("output %q", got)
	}
	_ = sh.Close()
	// The connection stays usable after the command shell closed.
	if code, err := c.Exec(t.Context(), "exit 0", nil, nil, nil); err != nil || code != 0 {
		t.Fatalf("connection closed with the shell: %d %v", code, err)
	}
	if _, err := c.CommandShell(t.Context(), "tty", 0, 80); fault.CodeOf(err) != fault.InvalidValue {
		t.Fatalf("size not checked: %v", err)
	}
}
