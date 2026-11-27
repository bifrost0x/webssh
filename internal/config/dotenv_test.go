package config

import (
	"encoding/base64"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// dotenvAnswer is what testdata/pyprobe.py reports for load_dotenv.
type dotenvAnswer struct {
	Error    string     `json:"error,omitempty"`
	Set      [][]string `json:"set,omitempty"`
	Changed  []string   `json:"changed,omitempty"`
	BadLines []int      `json:"bad_lines,omitempty"`
}

type dotenvCase struct {
	File   string            `json:"file"` // base64
	Env    map[string]string `json:"env"`
	Python dotenvAnswer      `json:"python"`
}

// fixedDotenvFiles pin the rules of python-dotenv: quotes, escapes,
// export, comments, interpolation and the statements it skips.
var fixedDotenvFiles = []string{
	"",
	"A=1\nB=2\n",
	"A=1",
	"export A=1\nexport\tB = 2 \n",
	"exportA=1\nexport =1\nexport\n",
	"A='single quoted'\nB=\"double quoted\"\n",
	`A='it\'s'` + "\n" + `B="say \"hi\""` + "\n",
	`A="tab\tnewline\nreturn\rbell\abs\bff\fvt\vbackslash\\quote\'x\zend"` + "\n",
	`A='tab\tnewline\nbackslash\\quote\'x'` + "\n",
	"A=\"line one\nline two\"\nB=after\n",
	"A='line one\nline two'\n",
	"A=\"unterminated\nB=2\n",
	"A='unterminated\nB=2\n",
	"A=value # comment\nB=value#not a comment\nC= # empty\nD=#kept\n",
	"A=\"quoted\" # comment\nB=\"quoted\" trailing\nC=2\n",
	"# comment\n  # indented comment\n\n\nA=1\n",
	"A\nB=\nC= \nD=2\n",
	"bad line\nA=1\n  another bad line\n\nB=2\n",
	"A=1\r\nB=2\rC=3\n",
	"\ufeffA=1\n",
	"\ufeff\ufeffA=1\n",
	"A = spaced \n  B=indented\n",
	"'quoted key'=1\n'with=equals'=2\n''=3\n",
	"A=${HOME_X}\nB=${A}\nC=${MISSING:-default}\nD=${MISSING}\nE=${A:-x}${A}\n",
	"A=${SET}\nSET=override\nB=${SET}\n",
	"A=$NOBRACE ${UNCLOSED\nB=${X:y} ${:-d} ${}\n",
	"A=1\nA=2\nB=${A}\n",
	"NONE\nB=${NONE:-d}\n",
	"A='${SET}'\nB=\"${SET}\"\n",
	"A=\x00\n",
	"A=x\x00y\n",
	"A=\xff\n",
	"A=é ü \u00a0\nB=x\u00a0# c\nC=x\u2028y\n",
	"A=x\x1c#c\nB=\x85\n",
	"A=1 \\\nB=2\n",
	"A=\"x\\\"\n",
	"SET=new\nEMPTY=new\nA=1\n",
	"#A=1\n#=x\n=x\nA==b\n",
	"A=1;B=2\nC=a b c\n",
	"   \n\t\n",
	"\n\n\nbad line\n",
	"A=\"x\" \"y\"\nB=1\n",
	"PYTHON_DOTENV_DISABLED=1\nA=1\n",
}

var dotenvEnvs = []map[string]string{
	{},
	{"SET": "from-env", "EMPTY": "", "HOME_X": "/home/x"},
}

var dotenvTokens = []string{
	"A", "B", "SET", "EMPTY", "export ", "export", "=", "==", " ", "\t", "  ", "#", " #", "'", "\"", "\\", "\\n", "\\'", "\\\"",
	"\n", "\r\n", "\r", "${A}", "${SET}", "${B:-d}", "${", "}", ":-", "x", "é", "\u00a0", "\u2028", "\x1c", "\x85",
	"\x00", "\ufeff", "\xff", "1", "value", "${EMPTY:-e}", "$", "{", ":",
}

var (
	dotenvKeys   = []string{"A", "B", "SET", "EMPTY", "export A", "'Q K'", "a.b-c", "", "#A", "é"}
	dotenvValues = []string{"", "1", "value", "two words", "'quoted'", "\"dq\"", "'it\\'s'", "\"a\\nb\\t\\\"c\"", "${A}", "${SET}",
		"${MISSING:-def}", "${EMPTY:-e}", "x${A}y", "'${SET}'", "\"${B}\"", "#hash", "a #c", "a#b", "\"multi\nline\"", "'open", "\"open",
		"\u00a0x", "x\u2028", "\\", "$", "${", "${A:x}"}
	dotenvSeps = []string{"=", " = ", "= ", " =", "\t=\t", "==", " "}
	dotenvEnds = []string{"\n", "\r\n", "\r", " # comment\n", " \n", "\n\n", "", " trailing\n"}
)

// randomDotenv builds a file of statements, or with a third of the
// chance a file of loose tokens.
func randomDotenv(r *rand.Rand) string {
	var b strings.Builder
	if r.IntN(3) == 0 {
		for range 1 + r.IntN(24) {
			b.WriteString(dotenvTokens[r.IntN(len(dotenvTokens))])
		}
		return b.String()
	}
	pick := func(list []string) string { return list[r.IntN(len(list))] }
	for range 1 + r.IntN(6) {
		b.WriteString(pick(dotenvKeys) + pick(dotenvSeps) + pick(dotenvValues) + pick(dotenvEnds))
	}
	return b.String()
}

func dotenvCases(n int) []dotenvCase {
	r := rand.New(rand.NewPCG(27, 11))
	var out []dotenvCase
	for _, f := range fixedDotenvFiles {
		for _, env := range dotenvEnvs {
			out = append(out, dotenvCase{File: base64.StdEncoding.EncodeToString([]byte(f)), Env: env})
		}
	}
	for range n {
		f := randomDotenv(r)
		out = append(out, dotenvCase{File: base64.StdEncoding.EncodeToString([]byte(f)), Env: dotenvEnvs[r.IntN(len(dotenvEnvs))]})
	}
	return out
}

func compareDotenv(t *testing.T, c dotenvCase) bool {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(c.File)
	if err != nil {
		t.Fatal(err)
	}
	got, bad, err := parseDotenv(data, lookupMap(c.Env))
	fail := func(format string, args ...any) bool {
		t.Errorf("file %q env %v: "+format, append([]any{data, c.Env}, args...)...)
		return false
	}
	if len(c.Python.Changed) > 0 {
		return fail("python-dotenv changed %v", c.Python.Changed)
	}
	if !slices.Equal(nonNilInts(bad), nonNilInts(c.Python.BadLines)) {
		return fail("skipped lines: Go %v, Python %v", bad, c.Python.BadLines)
	}
	if c.Python.Error != "" {
		if err == nil {
			return fail("Python fails with %s, Go adds %v", c.Python.Error, got)
		}
		return true
	}
	if err != nil {
		return fail("Go fails with %v, Python adds %v", err, c.Python.Set)
	}
	var want []EnvAssignment
	for _, kv := range c.Python.Set {
		want = append(want, EnvAssignment{Name: kv[0], Value: kv[1]})
	}
	if !slices.Equal(got, want) {
		return fail("Go %q, Python %q", got, want)
	}
	return true
}

func nonNilInts(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

const dotenvVectorFile = "python_dotenv.jsonl"

// TestPythonDotenvVectors compares the .env parser with the checked-in
// answers of python-dotenv.
func TestPythonDotenvVectors(t *testing.T) {
	if *update {
		o := requireOracle(t)
		cases := dotenvCases(800)
		for i := range cases {
			o.ask(t, map[string]any{"dotenv": cases[i].File, "env": cases[i].Env}, &cases[i].Python)
		}
		writeJSONLines(t, dotenvVectorFile, cases)
	}
	cases := readJSONLines[dotenvCase](t, dotenvVectorFile)
	if len(cases) < 800 {
		t.Fatalf("only %d vectors", len(cases))
	}
	failures := 0
	for _, c := range cases {
		if !compareDotenv(t, c) {
			if failures++; failures > 20 {
				t.Fatal("too many mismatches")
			}
		}
	}
}

// TestPythonDotenvLive compares many more random files with the oracle.
func TestPythonDotenvLive(t *testing.T) {
	if testing.Short() {
		t.Skip("long differential run")
	}
	o := requireOracle(t)
	r := rand.New(rand.NewPCG(5, 5))
	failures := 0
	for range 6000 {
		c := dotenvCase{File: base64.StdEncoding.EncodeToString([]byte(randomDotenv(r))), Env: dotenvEnvs[r.IntN(len(dotenvEnvs))]}
		o.ask(t, map[string]any{"dotenv": c.File, "env": c.Env}, &c.Python)
		if !compareDotenv(t, c) {
			if failures++; failures > 20 {
				t.Fatal("too many mismatches")
			}
		}
	}
}

func writeDotenv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), DotenvName)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadDotenvFile(t *testing.T) {
	path := writeDotenv(t, "A=1\nbad line\nB=${A}2\n")
	got, warns, err := ReadDotenv(path, lookupMap(map[string]string{"B": ""}))
	if err != nil || !slices.Equal(got, []EnvAssignment{{"A", "1"}}) {
		t.Fatalf("got %v %v", got, err)
	}
	if !hasWarning(warns, WarnDotenv, "", "line 2 cannot be parsed") || !hasWarning(warns, WarnDotenv, "", "1 variables were read") {
		t.Errorf("warnings %v", warns)
	}
	// Missing files and directories add nothing, as _is_file_or_fifo says.
	for _, p := range []string{filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		if got, warns, err := ReadDotenv(p, lookupMap(nil)); err != nil || got != nil || warns != nil {
			t.Errorf("%s: %v %v %v", p, got, warns, err)
		}
	}
	// A symbolic link is followed.
	link := filepath.Join(t.TempDir(), DotenvName)
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if got, _, err := ReadDotenv(link, lookupMap(nil)); err != nil || len(got) != 2 {
		t.Errorf("link: %v %v", got, err)
	}
}

func TestReadDotenvFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), DotenvName)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip("no FIFO:", err)
	}
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		_, _ = f.WriteString("FIFO=yes\n")
		_ = f.Close()
	}()
	got, _, err := ReadDotenv(path, lookupMap(nil))
	if err != nil || !slices.Equal(got, []EnvAssignment{{"FIFO", "yes"}}) {
		t.Errorf("FIFO: %v %v", got, err)
	}
}

// The Python release stops where load_dotenv raises; so does Go.
func TestReadDotenvRefuses(t *testing.T) {
	for name, content := range map[string]string{
		"invalid UTF-8": "A=\xff\n", "NUL": "A=x\x00\n", "name with =": "'A=B'=1\n",
	} {
		_, _, err := ReadDotenv(writeDotenv(t, content), lookupMap(nil))
		if e, ok := err.(*Error); !ok || !strings.HasPrefix(e.Message, "CONFIGURATION ERROR: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
	unreadable := writeDotenv(t, "A=1\n")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, _, err := ReadDotenv(unreadable, lookupMap(nil)); err == nil {
			t.Error("unreadable file accepted")
		}
	}
	big := writeDotenv(t, strings.Repeat("#", maxDotenvSize+1))
	if _, _, err := ReadDotenv(big, lookupMap(nil)); err == nil {
		t.Error("oversized file accepted")
	}
}

func TestDotenvDisabled(t *testing.T) {
	path := writeDotenv(t, "A=1\n")
	for v, disabled := range map[string]bool{
		"1": true, "true": true, "TRUE": true, "t": true, "Yes": true, "y": true, "Y": true, "ye\u017f": true,
		"0": false, "false": false, "": false, " 1": false, "on": false, "yes ": false, "\u0130": false,
	} {
		got, _, err := ReadDotenv(path, lookupMap(map[string]string{"PYTHON_DOTENV_DISABLED": v}))
		if err != nil || (got == nil) != disabled {
			t.Errorf("PYTHON_DOTENV_DISABLED=%q: %v %v", v, got, err)
		}
	}
}

func TestLoadDotenv(t *testing.T) {
	t.Setenv("WEBSSH_TEST_DOTENV_SET", "environment")
	t.Setenv("WEBSSH_TEST_DOTENV_NEW", "")
	if err := os.Unsetenv("WEBSSH_TEST_DOTENV_NEW"); err != nil {
		t.Fatal(err)
	}
	path := writeDotenv(t, "WEBSSH_TEST_DOTENV_SET=file\nWEBSSH_TEST_DOTENV_NEW=\"${WEBSSH_TEST_DOTENV_SET} and file\"\n")
	if _, err := LoadDotenv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("WEBSSH_TEST_DOTENV_SET"); v != "environment" {
		t.Errorf("the environment lost against the file: %q", v)
	}
	if v := os.Getenv("WEBSSH_TEST_DOTENV_NEW"); v != "environment and file" {
		t.Errorf("new variable %q", v)
	}
}

func FuzzDotenv(f *testing.F) {
	for _, s := range fixedDotenvFiles {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, bad, err := parseDotenv(data, lookupMap(map[string]string{"SET": "x"}))
		if err != nil {
			return
		}
		last := 0
		for _, l := range bad {
			if l < last || l < 1 {
				t.Fatalf("line numbers %v", bad)
			}
			last = l
		}
		seen := map[string]bool{}
		for _, a := range got {
			if a.Name == "" || seen[a.Name] || a.Name == "SET" || strings.ContainsAny(a.Name, "=\x00") || strings.ContainsRune(a.Value, 0) {
				t.Fatalf("assignment %q", a)
			}
			seen[a.Name] = true
		}
	})
}
