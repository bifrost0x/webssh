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
