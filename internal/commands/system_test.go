package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/oracletest"
)

// The embedded templates are app/resources/commands/system_commands.json
// of the Python release, byte for byte; its digest is recorded in
// testdata/python_system_commands.json.
func TestSystemCommandsEqualPythonResource(t *testing.T) {
	t.Parallel()
	type resource struct {
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	}
	rec := oracletest.Open(t, "testdata/python_system_commands.json")
	const name = "app/resources/commands/system_commands.json"
	python := oracletest.Ask(t, rec, name, name, func(r oracletest.Release) resource {
		raw, err := os.ReadFile(filepath.Join(r.Root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return resource{SHA256: hex.EncodeToString(sum[:]), Size: len(raw)}
	})
	sum := sha256.Sum256(systemCommandsJSON)
	if got := hex.EncodeToString(sum[:]); got != python.SHA256 || len(systemCommandsJSON) != python.Size {
		t.Fatalf("internal/commands/system_commands.json (%s, %d bytes) differs from %s of the Python release (%s, %d bytes)",
			got, len(systemCommandsJSON), name, python.SHA256, python.Size)
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
