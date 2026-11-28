package cron

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// pinnedChildEnv marks the process that TestHostZonesPinned starts with
// ZONEINFO pointing at a pinned zone database.
const pinnedChildEnv = "WEBSSH_CRON_PINNED_ZONEINFO"

// pinnedOffset is the offset of the pinned zone (+01:24), which no system
// zone has, so a run proves that the key loaded from the pinned database.
const pinnedOffset = 84 * 60

// absentZone is a key that no zone database has.
const absentZone = "posix/Pinned/Absent"

// TestHostZonesPinned checks the keys whose validity depends on the system
// zone database against a pinned one: a key the database has loads,
// whatever its name, and a key it lacks is refused. time.LoadLocation reads
// ZONEINFO once per process, so the Go answers come from a child process;
// the live mode also compares them with Python on the same database.
func TestHostZonesPinned(t *testing.T) {
	if os.Getenv(pinnedChildEnv) != "" {
		printPinnedAnswers(t)
		return
	}
	t.Parallel()
	dir := t.TempDir()
	for _, key := range hostZones {
		writePinnedZone(t, filepath.Join(dir, filepath.FromSlash(key)))
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHostZonesPinned$", "-test.count=1") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), pinnedChildEnv+"=1", "ZONEINFO="+dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v\n%s%s", err, out, stderr.Bytes())
	}
	var got []vector
	for line := range bytes.Lines(out) {
		if !bytes.HasPrefix(line, []byte("{")) {
			continue
		}
		var v vector
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("child answer %q: %v", line, err)
		}
		got = append(got, v)
	}
	want := pinnedWant()
	if len(got) != len(want) {
		t.Fatalf("child answered %d requests, want %d:\n%s", len(got), len(want), out)
	}
	for i, v := range got {
		if v.Req != want[i].Req || !same(v.Want, want[i].Want) {
			t.Errorf("%+v:\n go   %+v\n want %+v", v.Req, v.Want, want[i].Want)
		}
	}
	if o := startOracle(t, dir); o != nil {
		for _, v := range want {
			if py := o.ask(t, v.Req); !same(py, v.Want) {
				t.Errorf("%+v:\n python %+v\n want   %+v", v.Req, py, v.Want)
			}
		}
	}
}

// pinnedWant lists the requests on the pinned database and their answers:
// a daily run at 02:30 local time is at 01:06 UTC in the pinned zone.
func pinnedWant() []vector {
	after := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first := after.Add(150*time.Minute - pinnedOffset*time.Second).Unix()
	var out []vector
	for _, key := range hostZones {
		out = append(out,
			vector{request{Op: "parse", Expr: "* * * * *", Zone: key}, answer{OK: true}},
			vector{
				request{Op: "next", Expr: "30 2 * * *", Zone: key, After: after.Unix(), N: 2},
				answer{OK: true, Runs: []int64{first, first + 86400}},
			})
	}
	return append(out, vector{request{Op: "parse", Expr: "* * * * *", Zone: absentZone}, answer{Error: "invalid_schedule"}})
}

// printPinnedAnswers prints the Go answers of pinnedWant, one JSON line
// each, in the child process.
func printPinnedAnswers(t *testing.T) {
	for _, v := range pinnedWant() {
		line, err := json.Marshal(vector{v.Req, goAnswer(v.Req)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stdout.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

// writePinnedZone writes a TZif version 2 file of a zone without
// transitions at pinnedOffset, abbreviated PIN.
func writePinnedZone(t *testing.T, path string) {
	t.Helper()
	block := func(buf *bytes.Buffer, version byte) {
		buf.WriteString("TZif")
		buf.WriteByte(version)
		buf.Write(make([]byte, 15))
		// isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
		for _, n := range []uint32{0, 0, 0, 0, 1, 4} {
			_ = binary.Write(buf, binary.BigEndian, n)
		}
		_ = binary.Write(buf, binary.BigEndian, int32(pinnedOffset))
		buf.Write([]byte{0, 0}) // isdst, abbreviation index
		buf.WriteString("PIN\x00")
	}
	var buf bytes.Buffer
	block(&buf, '2')
	block(&buf, '2')
	buf.WriteString("\nPIN-1:24\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
