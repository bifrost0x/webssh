package remotecmd_test

import (
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

func TestScript(t *testing.T) {
	t.Parallel()
	body := "echo 'a'\nprintf '%s' \"$HOME\"; exit 3"
	c, err := remotecmd.Script(body, false)
	if err != nil || c.Line != `sh -c 'eval "$(cat)"'` || string(c.Stdin) != body {
		t.Fatalf("Script = %+v, %v", c, err)
	}
	f := &fakeExec{status: 3}
	res, err := remotecmd.Run(t.Context(), f, c)
	if err != nil || res.ExitStatus != 3 || string(f.stdin) != body || strings.Contains(f.line, "echo") {
		t.Fatalf("Run = %+v, %v; line %q", res, err, f.line)
	}
	c, err = remotecmd.Script("id", true)
	if err != nil || c.Line != `sudo -n -- sh -c 'eval "$(cat)"'` {
		t.Fatalf("sudo Script = %+v, %v", c, err)
	}
	for _, bad := range []string{"", "a\x00b", "\xff", strings.Repeat("x", remotecmd.MaxScript+1)} {
		if _, err := remotecmd.Script(bad, false); !fault.Is(err, fault.InvalidValue) {
			t.Errorf("Script(%q) = %v", bad[:min(len(bad), 8)], err)
		}
	}
}

func TestProgram(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("echo x\n", 2000) // larger than a Script
	c, err := remotecmd.Program(body)
	if err != nil || c.Line != `sh -c 'eval "$(cat)"'` || string(c.Stdin) != body {
		t.Fatalf("Program = %v", err)
	}
	for _, bad := range []string{"", "a\x00b", "\xff", strings.Repeat("x", remotecmd.MaxStdin+1)} {
		if _, err := remotecmd.Program(bad); !fault.Is(err, fault.InvalidValue) {
			t.Errorf("Program(%q) = %v", bad[:min(len(bad), 8)], err)
		}
	}
}
