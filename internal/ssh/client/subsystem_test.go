package client

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

func TestSubsystemRefusesOtherNames(t *testing.T) {
	c := dialExec(t)
	for _, name := range []string{"", "shell", "sftp ", "netconf"} {
		if _, err := c.Subsystem(t.Context(), name); fault.CodeOf(err) != fault.InvalidValue {
			t.Fatalf("%q: %v", name, err)
		}
	}
}

func TestSubsystemRefusedByServerKeepsConnection(t *testing.T) {
	c := dialExec(t)
	// The test server refuses every subsystem request.
	if _, err := c.Subsystem(t.Context(), SubsystemSFTP); err == nil {
		t.Fatal("refused subsystem reported as started")
	}
	if code, err := c.Exec(t.Context(), "exit 3", nil, nil, nil); err != nil || code != 3 {
		t.Fatalf("connection after a refused subsystem: %d %v", code, err)
	}
}

type foreignShell struct{ Shell }

func TestConnOfNamesTheShellsConnection(t *testing.T) {
	c := dialExec(t)
	sh, err := c.CommandShell(t.Context(), "cat", 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if ConnOf(sh) != c {
		t.Fatal("shell does not name its connection")
	}
	if ConnOf(foreignShell{}) != nil || ConnOf(nil) != nil {
		t.Fatal("a foreign shell names a connection")
	}
}
