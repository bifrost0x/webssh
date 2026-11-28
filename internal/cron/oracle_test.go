package cron

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/oracletest"
)

// The differential tests compare this package with app/automation_cron.py.
// The oracle is testdata/oracle.py, run by the repository's virtual
// environment (or WEBSSH_PYTHON). Its answers for the cases below are
// checked in as testdata/python_vectors.jsonl, so the comparison also
// runs without Python; -update rewrites the file from the oracle.
var update = flag.Bool("update", false, "rewrite the Python vectors in testdata from the oracle")

const (
	repoRoot    = "../.."
	vectorsFile = "python_vectors.jsonl"
	// digestAbove is the run count above which an answer keeps a digest
	// of the runs instead of the runs, which keeps the vectors small.
	digestAbove = 16
)

type request struct {
	Op      string `json:"op"`
	Expr    string `json:"expr"`
	Zone    string `json:"zone"`
	After   int64  `json:"after,omitempty"`
	AfterUS int64  `json:"after_us,omitempty"`
	N       int    `json:"n,omitempty"`
}

type answer struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Runs   []int64 `json:"runs,omitempty"`
	Count  int     `json:"count,omitempty"`
	Digest string  `json:"digest,omitempty"`
}

type vector struct {
	Req  request `json:"req"`
	Want answer  `json:"want"`
}

// compact replaces long run lists by their count and digest.
func (a answer) compact() answer {
	if len(a.Runs) <= digestAbove {
		return a
	}
	h := sha256.New()
	for _, r := range a.Runs {
		fmt.Fprintf(h, "%d\n", r)
	}
	a.Count, a.Digest, a.Runs = len(a.Runs), hex.EncodeToString(h.Sum(nil)), nil
	return a
}

// goAnswer answers a request with this package.
func goAnswer(req request) answer {
	fail := func(err error, runs []int64) answer {
		return answer{Error: string(fault.CodeOf(err)), Runs: runs}.compact()
	}
	s, err := Parse(req.Expr)
	if err != nil {
		return fail(err, nil)
	}
	loc, err := LoadZone(req.Zone)
	if err != nil {
		return fail(err, nil)
	}
	if req.Op == "parse" {
		return answer{OK: true}
	}
	after := time.Unix(req.After, req.AfterUS*1000)
	var runs []int64
	for range max(req.N, 1) {
		if after, err = s.Next(after, loc); err != nil {
			return fail(err, runs)
		}
		runs = append(runs, after.Unix())
	}
	return answer{OK: true, Runs: runs}.compact()
}

type oracle struct {
	in  *json.Encoder
	out *bufio.Scanner
}

func pythonPath() string {
	if p := os.Getenv("WEBSSH_PYTHON"); p != "" {
		return p
	}
	return filepath.Join(repoRoot, ".venv", "bin", "python")
}

// startOracle starts the Python oracle under -update and in the live and
// record modes of internal/oracletest; in replay mode it returns nil.
func startOracle(t testing.TB) *oracle {
	t.Helper()
	var python, root string
	switch {
	case *update:
		python = pythonPath()
		if _, err := os.Stat(python); err != nil {
			t.Fatalf("-update needs the Python oracle: %v", err)
		}
		var err error
		if root, err = filepath.Abs(repoRoot); err != nil {
			t.Fatal(err)
		}
	case oracletest.CurrentMode(t) != oracletest.Replay:
		rel := oracletest.RequireLive(t)
		python, root = rel.Python, rel.Root
	default:
		return nil
	}
	cmd := exec.CommandContext(t.Context(), python, "-I", "testdata/oracle.py", root) // #nosec G204 -- test oracle
	cmd.Env = []string{"LANG=C.UTF-8", "PATH=" + os.Getenv("PATH")}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	return &oracle{in: json.NewEncoder(stdin), out: sc}
}

func (o *oracle) ask(t testing.TB, req request) answer {
	t.Helper()
	if err := o.in.Encode(req); err != nil {
		t.Fatalf("oracle request: %v", err)
	}
	if !o.out.Scan() {
		t.Fatalf("oracle ended: %v", o.out.Err())
	}
	var a answer
	if err := json.Unmarshal(o.out.Bytes(), &a); err != nil {
		t.Fatalf("oracle answer: %v", err)
	}
	if strings.HasPrefix(a.Error, "crash:") {
		t.Fatalf("the Python release crashed on %+v: %s", req, a.Error)
	}
	return a.compact()
}

func same(a, b answer) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func TestPythonVectors(t *testing.T) {
	t.Parallel()
	cs := cases()
	if o := startOracle(t); o != nil {
		var out []vector
		for _, c := range cs {
			want := o.ask(t, c)
			if got := goAnswer(c); !same(got, want) {
				t.Errorf("%+v:\n go     %+v\n python %+v", c, got, want)
			}
			out = append(out, vector{c, want})
		}
		if *update {
			writeVectors(t, out)
		}
		return
	} else if *update {
		t.Fatal("-update needs the Python oracle")
	}
	vs := readVectors(t)
	if len(vs) != len(cs) {
		t.Fatalf("%d recorded vectors for %d cases; run with -update", len(vs), len(cs))
	}
	for i, v := range vs {
		if v.Req != cs[i] {
			t.Fatalf("vector %d is %+v, case is %+v; run with -update", i, v.Req, cs[i])
		}
		if got := goAnswer(v.Req); !same(got, v.Want) {
			t.Errorf("%+v:\n go     %+v\n python %+v", v.Req, got, v.Want)
		}
	}
}

// TestPythonZonesLive compares every key of the system zone database:
// whether it loads, and the runs around the transitions of three years.
func TestPythonZonesLive(t *testing.T) {
	t.Parallel()
	o := startOracle(t)
	if o == nil {
		oracletest.RequireLive(t)
	}
	keys := systemZones(t)
	after := time.Date(2025, 12, 31, 12, 0, 0, 0, time.UTC).Unix()
	for _, key := range keys {
		for _, expr := range []string{"30 2 * * *", "0,30 0-3 * 3,4,9,10,11 0"} {
			req := request{Op: "next", Expr: expr, Zone: key, After: after, N: 40}
			if got, want := goAnswer(req), o.ask(t, req); !same(got, want) {
				t.Errorf("%+v:\n go     %+v\n python %+v", req, got, want)
			}
		}
	}
}

// TestPythonRandomLive compares random expressions, zones and times.
func TestPythonRandomLive(t *testing.T) {
	t.Parallel()
	o := startOracle(t)
	if o == nil {
		oracletest.RequireLive(t)
	}
	rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 7)) // #nosec G404 -- test data
	n := 3000
	if testing.Short() {
		n = 300
	}
	keys := systemZones(t)
	for range n {
		req := randomCase(rng)
		if rng.IntN(2) == 0 {
			req.Zone = keys[rng.IntN(len(keys))]
		}
		if got, want := goAnswer(req), o.ask(t, req); !same(got, want) {
			t.Errorf("%+v:\n go     %+v\n python %+v", req, got, want)
		}
	}
}

// systemZones lists the keys of the system zone database.
func systemZones(t *testing.T) []string {
	t.Helper()
	const root = "/usr/share/zoneinfo"
	var keys []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		keys = append(keys, rel)
		return nil
	})
	if err != nil || len(keys) == 0 {
		t.Skipf("no system zone database: %v", err)
	}
	return keys
}

func writeVectors(t testing.TB, vs []vector) {
	t.Helper()
	var buf bytes.Buffer
	for _, v := range vs {
		line, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join("testdata", vectorsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readVectors(t testing.TB) []vector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", vectorsFile))
	if err != nil {
		t.Fatal(err)
	}
	var out []vector
	for line := range bytes.Lines(data) {
		var v vector
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}
