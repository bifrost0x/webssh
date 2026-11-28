package quota

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/oracletest"
)

// The differential tests compare the policy with app/quota_manager.py and
// the storage rule with bounded_text of app/storage_quota.py. The oracle
// is testdata/oracle.py, run with the Python release (internal/oracletest,
// WEBSSH_PYTHON_ROOT); its answers are checked in as
// testdata/python_vectors.jsonl, and -update rewrites them.
var update = flag.Bool("update", false, "rewrite the Python vectors in testdata from the oracle")

type request struct {
	Op     string              `json:"op"`
	Limits map[string][2]int64 `json:"limits,omitempty"`
	Steps  [][]any             `json:"steps,omitempty"`
	Value  string              `json:"value,omitempty"`
	Max    int64               `json:"max,omitempty"`
	Legacy *string             `json:"legacy,omitempty"`
}

type answer struct {
	OK      bool     `json:"ok"`
	Error   string   `json:"error,omitempty"`
	Results []string `json:"results,omitempty"`
}

type vector struct {
	Req  request `json:"req"`
	Want answer  `json:"want"`
}

func limitsOf(m map[string][2]int64) map[string]Limit {
	out := map[string]Limit{}
	for k, v := range m {
		out[k] = Limit{Global: v[0], PerUser: v[1]}
	}
	return out
}

// goAnswer answers with this package. Error texts of the limit checks are
// not compared: Python refuses them at start with its own words, Go with
// the configuration errors of internal/config.
func goAnswer(t testing.TB, req request) answer {
	switch req.Op {
	case "limits":
		if _, err := New(limitsOf(req.Limits)); err != nil {
			return answer{Error: "refused"}
		}
		return answer{OK: true}
	case "sequence":
		p, err := New(limitsOf(req.Limits))
		if err != nil {
			t.Fatalf("limits %v: %v", req.Limits, err)
		}
		var held []func()
		var out []string
		for _, s := range req.Steps {
			if s[0] == "reserve" {
				release, err := p.Reserve(context.Background(), s[1].(string), int64(s[2].(float64)), int64(s[3].(float64)))
				switch {
				case err == nil:
					out = append(out, "ok")
				case fault.Is(err, fault.Busy):
					e, _ := fault.From(err)
					out = append(out, e.Message)
				default:
					t.Fatalf("reserve %v: %v", s, err)
				}
				held = append(held, release)
				continue
			}
			if r := held[int(s[1].(float64))]; r != nil {
				r()
			}
			out = append(out, "released")
		}
		return answer{OK: true, Results: out}
	default:
		stored := int64(-1)
		if req.Legacy != nil {
			stored = int64(len(*req.Legacy))
		}
		if WithinStorage(int64(len(req.Value)), stored, req.Max) {
			return answer{OK: true}
		}
		return answer{Error: "value is too large"}
	}
}

func normalize(a answer, op string) answer {
	if op == "limits" && !a.OK {
		a.Error = "refused"
	}
	return a
}

// roundTrip gives a request the shape it has after JSON, as the oracle
// and the recorded vectors see it.
func roundTrip(t testing.TB, req request) request {
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var out request
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

type oracle struct {
	in  *json.Encoder
	out *bufio.Scanner
}

// startOracle starts the Python oracle under -update and in the live and
// record modes of internal/oracletest; in replay mode it returns nil.
func startOracle(t testing.TB) *oracle {
	t.Helper()
	var python, root string
	switch {
	case *update:
		rel := oracletest.Require(t)
		python, root = rel.Python, rel.Root
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
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	return &oracle{in: json.NewEncoder(stdin), out: sc}
}

func (o *oracle) ask(t testing.TB, req request) answer {
	t.Helper()
	if err := o.in.Encode(req); err != nil {
		t.Fatal(err)
	}
	if !o.out.Scan() {
		t.Fatalf("oracle ended: %v", o.out.Err())
	}
	var a answer
	if err := json.Unmarshal(o.out.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	return normalize(a, req.Op)
}

func defaults() map[string][2]int64 {
	out := map[string][2]int64{}
	for k, l := range DefaultLimits {
		out[k] = [2]int64{l.Global, l.PerUser}
	}
	return out
}

func with(kind string, g, p int64) map[string][2]int64 {
	m := defaults()
	m[kind] = [2]int64{g, p}
	return m
}

// cases are the recorded cases in a fixed order.
func cases(t testing.TB) []request {
	var out []request
	out = append(out, request{Op: "limits", Limits: defaults()})
	for _, kind := range Kinds() {
		for _, l := range [][2]int64{{1, 1}, {2, 1}, {2, 2}, {3, 4}, {0, 0}, {1, 0}, {0, 1}, {-1, -1}, {5, -2}, {1 << 40, 1<<40 - 1}} {
			out = append(out, request{Op: "limits", Limits: with(kind, l[0], l[1])})
		}
	}
	missing := defaults()
	delete(missing, Transfer)
	out = append(out, request{Op: "limits", Limits: missing})
	for _, s := range []struct {
		value, legacy string
		hasLegacy     bool
		max           int64
	}{
		{"abc", "", false, 3}, {"abcd", "", false, 3}, {"\u00e4\u00f6", "", false, 3}, {"\u00e4\u00f6", "", false, 4},
		{"abcd", "abcde", true, 3}, {"abcdef", "abcde", true, 3}, {"abcde", "abcde", true, 3},
		{"", "", false, 0}, {"x", "", true, 0}, {"\u20ac\u20ac", "aaaaaa", true, 1}, {"\u20ac\u20ac\u20ac", "aaaaaa", true, 1},
	} {
		req := request{Op: "bounded", Value: s.value, Max: s.max}
		if s.hasLegacy {
			req.Legacy = new(s.legacy)
		}
		out = append(out, req)
	}
	rng := rand.New(rand.NewPCG(20261127, 2)) // #nosec G404 -- test data
	for range 120 {
		out = append(out, randomSequence(rng))
	}
	for i := range out {
		out[i] = roundTrip(t, out[i])
	}
	return out
}

// randomSequence reserves and releases with small limits, several users
// and double releases.
func randomSequence(rng *rand.Rand) request {
	limits := defaults()
	for _, kind := range Kinds() {
		g := 1 + rng.Int64N(6)
		p := 1 + rng.Int64N(g)
		if fairSlots[kind] && p == g {
			g++
		}
		limits[kind] = [2]int64{g, p}
	}
	var steps [][]any
	reserves := 0
	for range 5 + rng.IntN(40) {
		if reserves > 0 && rng.IntN(3) == 0 {
			steps = append(steps, []any{"release", rng.IntN(reserves)})
			continue
		}
		kind := Kinds()[rng.IntN(len(Kinds()))]
		steps = append(steps, []any{"reserve", kind, 1 + rng.IntN(3), 1 + rng.IntN(3)})
		reserves++
	}
	return request{Op: "sequence", Limits: limits, Steps: steps}
}

func TestPythonVectors(t *testing.T) {
	t.Parallel()
	cs := cases(t)
	file := filepath.Join("testdata", "python_vectors.jsonl")
	if o := startOracle(t); o != nil {
		var buf bytes.Buffer
		for _, c := range cs {
			want := o.ask(t, c)
			if got := goAnswer(t, c); !reflect.DeepEqual(got, want) {
				t.Errorf("%+v:\n go     %+v\n python %+v", c, got, want)
			}
			line, _ := json.Marshal(vector{c, want})
			buf.Write(append(line, '\n'))
		}
		if *update {
			if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return
	} else if *update {
		t.Fatal("-update needs the Python oracle")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for line := range bytes.Lines(data) {
		var v vector
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatal(err)
		}
		if i >= len(cs) || !reflect.DeepEqual(v.Req, cs[i]) {
			t.Fatalf("vector %d does not match the cases; run with -update", i)
		}
		if got := goAnswer(t, v.Req); !reflect.DeepEqual(got, v.Want) {
			t.Errorf("%+v:\n go     %+v\n python %+v", v.Req, got, v.Want)
		}
		i++
	}
	if i != len(cs) {
		t.Fatalf("%d vectors for %d cases; run with -update", i, len(cs))
	}
}

func TestPythonRandomLive(t *testing.T) {
	t.Parallel()
	o := startOracle(t)
	if o == nil {
		oracletest.RequireLive(t)
	}
	rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 3)) // #nosec G404 -- test data
	for range 2000 {
		c := roundTrip(t, randomSequence(rng))
		if got, want := goAnswer(t, c), o.ask(t, c); !reflect.DeepEqual(got, want) {
			t.Fatalf("%+v:\n go     %+v\n python %+v", c, got, want)
		}
	}
}
