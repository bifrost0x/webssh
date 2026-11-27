//go:build e2e

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/hostops"
)

// The fixture answers the real collector programs with samples the real
// parsers accept, and nothing else.
func TestFixtureExecAnswersTheCollectors(t *testing.T) {
	run := func(script string) (string, error) {
		program, err := os.ReadFile("../../internal/hostops/scripts/" + script)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		_, err = fixtureExec{}.Exec(t.Context(), "sh -s", bytes.NewReader(program), &out, nil)
		return out.String(), err
	}
	out, err := run("insights_stats.sh")
	if err != nil {
		t.Fatal(err)
	}
	if st, err := hostops.ParseStats(out); err != nil || st.OSName != "Reload fixture Linux" || st.Disk == nil {
		t.Fatalf("stats %+v %v", st, err)
	}
	out, err = run("runtime_inventory.sh")
	if err != nil {
		t.Fatal(err)
	}
	if inv, err := hostops.ParseInventory(out); err != nil || inv.Systemd == nil || inv.Systemd.State != "running" {
		t.Fatalf("inventory %+v %v", inv, err)
	}
	if _, err := (fixtureExec{}).Exec(t.Context(), "rm -rf /", strings.NewReader(""), &bytes.Buffer{}, nil); err == nil {
		t.Fatal("an unknown command was answered")
	}
}
