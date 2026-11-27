package commands

import (
	"bytes"
	"os"
	"testing"
)

// The embedded templates are app/resources/commands/system_commands.json
// as long as the Python release ships it.
func TestSystemCommandsEqualPythonResource(t *testing.T) {
	t.Parallel()
	python, err := os.ReadFile("../../app/resources/commands/system_commands.json")
	if os.IsNotExist(err) {
		t.Skip("the Python release is not in this tree")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(python, systemCommandsJSON) {
		t.Fatal("internal/commands/system_commands.json differs from app/resources/commands/system_commands.json")
	}
	items, err := systemCommands()
	if err != nil || len(items) != 312 {
		t.Fatalf("%d templates, %v", len(items), err)
	}
	for _, it := range items {
		if !validStoredCommand(it) {
			t.Fatalf("template %s is not a valid command", it)
		}
	}
}
