package automation

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/oracletest"
)

// The next slot of a schedule is differentially tested against next_due of
// app/automation_cron.py over a whole year with daylight-saving changes in
// several zones (northern and southern hemisphere, a 30-minute shift,
// zones without DST). The oracle is the cron oracle of internal/cron, run
// with the Python release (internal/oracletest); its answers
// are checked in as testdata/next_due_year.jsonl, so the comparison also
// runs without Python. -update-next rewrites the file.
var updateNext = flag.Bool("update-next", false, "rewrite testdata/next_due_year.jsonl from the Python oracle")

const nextVectors = "testdata/next_due_year.jsonl"

type yearCase struct {
	Op    string `json:"op"`
	Expr  string `json:"expr"`
	Zone  string `json:"zone"`
	After int64  `json:"after"`
	N     int    `json:"n"`
}

type yearAnswer struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Count  int    `json:"count"`
	Digest string `json:"digest"`
	First  int64  `json:"first"`
	Last   int64  `json:"last"`
}

func yearCases() []yearCase {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	var out []yearCase
	for _, c := range []struct {
		expr, zone string
		n          int
	}{
		{"30 2 * * *", "Europe/Berlin", 366}, // in the spring gap, twice in the autumn fold
		{"0 * * * *", "Europe/Berlin", 8760}, // every hour of the year
		{"*/15 1-3 * 3,10,11 *", "Europe/Berlin", 4000},
		{"30 1 * * 0", "America/New_York", 53}, // Sunday 01:30, the US change times
		{"0 2 * * *", "America/New_York", 366},
		{"*/30 * * * *", "Australia/Lord_Howe", 17520}, // 30-minute DST
		{"0 0 * * *", "America/Santiago", 366},         // midnight changes
		{"15 3 1 * *", "Europe/London", 12},
		{"45 23 31 * *", "Pacific/Auckland", 7}, // southern hemisphere, the 31st only
		{"0 0 * * 1-5", "Asia/Kolkata", 261},    // no DST, half-hour offset
		{"0 9 * * *", "UTC", 365},
		{"0 9 1-7 * 1", "Europe/Berlin", 60}, // Vixie rule: day or weekday
		{"0 4 * * 7", "Asia/Tehran", 52},     // no DST since 2022
	} {
		out = append(out, yearCase{Op: "next", Expr: c.expr, Zone: c.zone, After: start, N: c.n})
	}
	return out
}

func compactYear(runs []int64, err string) yearAnswer {
	a := yearAnswer{OK: err == "", Error: err, Count: len(runs)}
	h := sha256.New()
	for _, r := range runs {
		fmt.Fprintf(h, "%d\n", r)
	}
	a.Digest = hex.EncodeToString(h.Sum(nil))
	if len(runs) > 0 {
		a.First, a.Last = runs[0], runs[len(runs)-1]
	}
	return a
}

// goYear chains NextDue as a schedule does: the preview's next runs, the
// approval's first slot and the slot after each dispatch.
func goYear(c yearCase) yearAnswer {
	after := time.Unix(c.After, 0)
	var runs []int64
	for range c.N {
		next, err := NextDue(c.Expr, c.Zone, after)
		if err != nil {
			return compactYear(runs, "invalid_schedule")
		}
		runs = append(runs, next.Unix())
		after = next
	}
	return compactYear(runs, "")
}

// pythonYear asks the Python oracle under -update-next and in the live and
// record modes of internal/oracletest; in replay mode it returns nil and
// the recorded answers are used.
func pythonYear(t *testing.T) []yearAnswer {
	t.Helper()
	var python, root string
	switch {
	case *updateNext:
		rel := oracletest.Require(t)
		python, root = rel.Python, rel.Root
	case oracletest.CurrentMode(t) != oracletest.Replay:
		rel := oracletest.RequireLive(t)
		python, root = rel.Python, rel.Root
	default:
		return nil
	}
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, c := range yearCases() {
		if err := enc.Encode(c); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(t.Context(), python, "-I", filepath.Join("..", "cron", "testdata", "oracle.py"), root) // #nosec G204 -- test oracle
	cmd.Env = []string{"LANG=C.UTF-8", "PATH=" + os.Getenv("PATH")}
	cmd.Stdin = &in
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	var answers []yearAnswer
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var raw struct {
			OK    bool    `json:"ok"`
			Error string  `json:"error"`
			Runs  []int64 `json:"runs"`
		}
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		answers = append(answers, compactYear(raw.Runs, raw.Error))
	}
	return answers
}

func TestNextDueOverAYearMatchesPython(t *testing.T) {
	t.Parallel()
	cases := yearCases()
	want := pythonYear(t)
	if want == nil {
		if *updateNext {
			t.Fatal("-update-next needs the Python oracle")
		}
		data, err := os.ReadFile(nextVectors)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			var v struct {
				Case yearCase   `json:"case"`
				Want yearAnswer `json:"want"`
			}
			if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
			if len(want) >= len(cases) || v.Case != cases[len(want)] {
				t.Fatalf("vector %d does not match its case; run with -update-next", len(want))
			}
			want = append(want, v.Want)
		}
	} else if *updateNext {
		var b bytes.Buffer
		for i, c := range cases {
			line, _ := json.Marshal(map[string]any{"case": c, "want": want[i]})
			b.Write(append(line, '\n'))
		}
		if err := os.WriteFile(nextVectors, b.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(want) != len(cases) {
		t.Fatalf("%d answers for %d cases; run with -update-next", len(want), len(cases))
	}
	for i, c := range cases {
		if got := goYear(c); got != want[i] {
			t.Errorf("%s in %s:\n go     %+v\n python %+v", c.Expr, c.Zone, got, want[i])
		}
	}
}
