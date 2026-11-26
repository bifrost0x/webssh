package idna2003

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// The Python oracle is testdata/oracle.py, run by the repository's virtual
// environment or WEBSSH_PYTHON. Its vectors and digests are checked in,
// so the comparison also runs where Python is missing.

const repoRoot = "../.."

func pythonPath() string {
	if p := os.Getenv("WEBSSH_PYTHON"); p != "" {
		return p
	}
	return filepath.Join(repoRoot, ".venv", "bin", "python")
}

// python runs the oracle with args and returns its output, or skips when
// no interpreter is available. WEBSSH_REQUIRE_PYTHON turns the skip into
// a failure, so a CI job that is meant to compare cannot pass silently.
func python(t *testing.T, stdin []byte, args ...string) []byte {
	t.Helper()
	p := pythonPath()
	if _, err := os.Stat(p); err != nil {
		if os.Getenv("WEBSSH_REQUIRE_PYTHON") != "" {
			t.Fatalf("Python oracle required but missing: %v", err)
		}
		t.Skip("no Python interpreter for the oracle (set WEBSSH_PYTHON)")
	}
	cmd := exec.CommandContext(t.Context(), p, append([]string{"-I", "testdata/oracle.py"}, args...)...) // #nosec G204 -- fixed test interpreter and script
	cmd.Env = []string{"LANG=C.UTF-8", "PATH=" + os.Getenv("PATH")}
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle %v: %v", args, err)
	}
	return out
}

type vector struct {
	In  string  `json:"in"`
	Out *string `json:"out"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/python_vectors.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var out []vector
	for line := range bytes.SplitSeq(bytes.TrimSpace(raw), []byte("\n")) {
		var v vector
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		out = append(out, v)
	}
	if len(out) < 10000 {
		t.Fatalf("vector file is incomplete: %d vectors", len(out))
	}
	return out
}

func check(t *testing.T, in string, want *string) {
	t.Helper()
	got, err := Encode(in)
	switch {
	case want == nil && err == nil:
		t.Errorf("%+q: Go %q, Python refuses", in, got)
	case want != nil && err != nil:
		t.Errorf("%+q: Go refuses (%v), Python %q", in, err, *want)
	case want != nil && got != *want:
		t.Errorf("%+q: Go %q, Python %q", in, got, *want)
	case err != nil && !errors.Is(err, ErrInvalid):
		t.Errorf("%+q: error %v is not ErrInvalid", in, err)
	}
}

func TestVectorsMatchPython(t *testing.T) {
	t.Parallel()
	refused := 0
	for _, v := range loadVectors(t) {
		check(t, v.In, v.Out)
		if v.Out == nil {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("the corpus has no refused names")
	}
}

func TestKnownNames(t *testing.T) {
	t.Parallel()
	ok := func(s string) *string { return &s }
	for in, want := range map[string]*string{
		"":                      ok(""),
		"Example.COM":           ok("Example.COM"),
		"bücher.example":        ok("xn--bcher-kva.example"),
		"BÜCHER.example":        ok("xn--bcher-kva.example"),
		"münchen\u3002de":       ok("xn--mnchen-3ya.de"),
		"ü.":                    ok("xn--tda."),
		"中文.cn":                 ok("xn--fiq228c.cn"),
		"stra\u00dfe.de":        ok("strasse.de"),
		"a\u00adb.de\u3002":     ok("ab.de."),
		"a..b":                  nil,
		"ü..b":                  nil,
		strings.Repeat("a", 64): nil,
		"xn--ü":                 nil,
		"\u05d0a":               nil,
		"a\u200eü":              nil,
		"\xff":                  nil,
	} {
		check(t, in, want)
	}
}

func digest(form string) string {
	h := sha256.New()
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r < 0xE000 {
			continue
		}
		out, err := Encode(fmt.Sprintf(form, string(r)))
		if err != nil {
			out = "!"
		}
		h.Write([]byte(out + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestEveryCodePointMatchesPython encodes every code point in the contexts
// of oracle.py and compares one digest per context with Python's.
func TestEveryCodePointMatchesPython(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("exhaustive")
	}
	t.Parallel()
	raw, err := os.ReadFile("testdata/python_digests.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if want["unicode"] != unicodeVersion {
		t.Fatalf("digests of Unicode %s, tables of %s", want["unicode"], unicodeVersion)
	}
	for name, form := range map[string]string{
		"alone": "%s", "after_a": "a%s", "before_mark": "%s\u0301", "in_rtl": "\u05d0%s\u05d0", "label": "%s.example",
	} {
		if got := digest(form); got != want[name] {
			t.Errorf("%s: digest %s, Python %s; run TestLivePythonOracle to see the code points", name, got, want[name])
		}
	}
}

// TestLivePythonOracle compares every code point in every context with a
// running interpreter and names the first differences.
func TestLivePythonOracle(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("exhaustive")
	}
	var in bytes.Buffer
	var names []string
	for r := rune(0); r <= utf8.MaxRune; r += 7 {
		if r >= 0xD800 && r < 0xE000 {
			continue
		}
		for _, form := range []string{"%s", "x%s\u0308y", "%s\u0327\u0301", "\u0627%s"} {
			names = append(names, fmt.Sprintf(form, string(r)))
		}
	}
	for _, n := range names {
		line, _ := json.Marshal(n)
		in.Write(append(line, '\n'))
	}
	out := python(t, in.Bytes(), "serve")
	sc := bufio.NewScanner(bytes.NewReader(out))
	failures := 0
	for i := 0; sc.Scan(); i++ {
		var want *string
		if err := json.Unmarshal(sc.Bytes(), &want); err != nil {
			t.Fatal(err)
		}
		got, err := Encode(names[i])
		if (err == nil) != (want != nil) || want != nil && got != *want {
			failures++
			if failures <= 20 {
				t.Errorf("%+q: Go %q %v, Python %v", names[i], got, err, deref(want))
			}
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<refused>"
	}
	return *s
}

// TestTablesMatchGenerator regenerates tables.go from the interpreter and
// compares it with the checked-in file.
func TestTablesMatchGenerator(t *testing.T) {
	got := python(t, nil, "tables")
	want, err := os.ReadFile("tables.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatal("tables.go differs from oracle.py tables; regenerate it (see testdata/oracle.py)")
	}
}

func FuzzEncode(f *testing.F) {
	for _, s := range []string{"bücher.de", "a..b", "\u05d0\u05d1", "\ufb01.example", "\u1100\u1161\u11a8", "xn--a", "a\u0301\u0323"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := Encode(s)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v", err)
			}
			return
		}
		if !isASCII(out) {
			t.Fatalf("%+q encoded to non-ASCII %q", s, out)
		}
		for i, label := range strings.Split(out, ".") {
			if len(label) >= maxLabel || label == "" && i < strings.Count(out, ".") {
				t.Fatalf("%+q encoded to an invalid label in %q", s, out)
			}
		}
	})
}
