package github

import (
	"bufio"
	"encoding/json"
	"flag"
	"math/rand/v2"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/oracletest"
)

// The differential tests compare the pure functions of this package with
// the Python release, answered by testdata/pyprobe.py through its
// interpreter (internal/oracletest, WEBSSH_PYTHON_ROOT). The answers are
// checked in (testdata/python_vectors.json), so the comparison also runs
// without Python; -update records them again.
var update = flag.Bool("update", false, "record the Python answers in testdata/python_vectors.json")

const vectorsFile = "testdata/python_vectors.json"

type probeRequest struct {
	Op     string `json:"op"`
	Value  any    `json:"value"`
	Root   string `json:"root,omitempty"`
	Status int    `json:"status,omitempty"`
	Body   string `json:"body,omitempty"`
	Login  string `json:"login,omitempty"`
}

type probeCase struct {
	Request probeRequest    `json:"request"`
	Answer  json.RawMessage `json:"answer"`
}

func askPython(t *testing.T, reqs []probeRequest) []json.RawMessage {
	t.Helper()
	rel := oracletest.Require(t)
	cmd := exec.CommandContext(t.Context(), rel.Python, "testdata/pyprobe.py", rel.Root) // #nosec G204 -- test oracle
	cmd.Env = []string{"LANG=C.UTF-8", "PATH=" + os.Getenv("PATH"), "DATA_DIR=" + t.TempDir(), "PYTHONWARNINGS=ignore",
		"SECRET_KEY=probe-test-only-0123456789abcdef0123456789"}
	var in strings.Builder
	enc := json.NewEncoder(&in)
	for _, r := range reqs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	cmd.Stdin = strings.NewReader(in.String())
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	var answers []json.RawMessage
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "{") && !strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "\"") && line != "null" {
			continue // the application's start-up notices
		}
		answers = append(answers, json.RawMessage(line))
	}
	if len(answers) != len(reqs) {
		t.Fatalf("oracle answered %d of %d requests", len(answers), len(reqs))
	}
	return answers
}

// redirectInputs are hand-picked edge cases plus random strings over the
// characters urlsplit treats specially.
func redirectInputs() []string {
	cb := "/auth/github/callback"
	out := []string{
		"https://ssh.example.com" + cb, "HTTPS://SSH.Example.com" + cb, "http://localhost" + cb, "http://LOCALHOST:5000" + cb,
		"http://127.0.0.1" + cb, "http://[::1]:8080" + cb, "http://[::1]" + cb, "http://ssh.example.com" + cb,
		"https://ssh.example.com" + cb + "?", "https://ssh.example.com" + cb + "?a=1", "https://ssh.example.com" + cb + "#",
		"https://ssh.example.com" + cb + "#f", "https://user@ssh.example.com" + cb, "https://@ssh.example.com" + cb,
		"https://u:p@ssh.example.com" + cb, "https://ssh.example.com:443" + cb, "https://ssh.example.com:0" + cb,
		"https://ssh.example.com:65536" + cb, "https://ssh.example.com:x" + cb, "https://ssh.example.com:" + cb,
		"https://ssh.example.com:００" + cb, "https://[fe80::1%25eth0]" + cb, "https://[fe80::1%]" + cb,
		"https://[1.2.3.4]" + cb, "https://[v1.x]" + cb, "https://[v.x]" + cb, "https://[::1" + cb, "https://::1]" + cb,
		"https://a[::1]" + cb, "https://[::1]x" + cb, "https://[::ffff:1.2.3.4]" + cb, "https://[::g]" + cb,
		"https://bücher.example" + cb, "https://a℀b" + cb, "https://ａ" + cb, "https://example.com／x" + cb,
		"https://ssh.example.com/auth/git\thub/callback", "\x00 https://ssh.example.com" + cb, "https://ssh.example.com" + cb + "/",
		"https://ssh.example.com/AUTH/github/callback", "//ssh.example.com" + cb, "https:/ssh.example.com" + cb,
		"ftp://ssh.example.com" + cb, "https://" + cb, "https://ssh.example.com/prefix" + cb,
		"https://K.example" + cb, "http://localhoſt" + cb, "https://xn--bcher-kva.example" + cb, "https://" + strings.Repeat("a", 2030) + cb,
		"1https://ssh.example.com" + cb, "h+ttps://ssh.example.com" + cb, "https://ssh.example.com:+1" + cb,
		"https://[::1]:99999" + cb, "https://[::1]:" + cb, "http://[::1]:80@x" + cb, "http://x@[::1]" + cb,
	}
	r := rand.New(rand.NewPCG(7, 11))
	alphabet := []string{"https", "http", ":", "/", "//", "[", "]", "@", "?", "#", "%", "::1", "localhost", "a", "1", "\t", " ", "v1.", "ä", "℀", cb}
	for range 400 {
		var b strings.Builder
		for range 1 + r.IntN(8) {
			b.WriteString(alphabet[r.IntN(len(alphabet))])
		}
		out = append(out, b.String())
	}
	netloc := []string{"[", "]", "@", ":", "::1", "localhost", "127.0.0.1", "v1.", "%", "a", "8080", "ä", "＠", "K", "fe80::1", "\t", "x"}
	for range 400 {
		var b strings.Builder
		b.WriteString([]string{"https://", "http://", "HTTP://"}[r.IntN(3)])
		for range 1 + r.IntN(6) {
			b.WriteString(netloc[r.IntN(len(netloc))])
		}
		b.WriteString([]string{cb, cb + "?", "/x" + cb, cb + "#x"}[r.IntN(4)])
		out = append(out, b.String())
	}
	return out
}

func orgInputs() []any {
	return []any{
		"lab-org", " Lab-Org , lab-org,,other ", "", ",", "-bad", "bad-", "a", strings.Repeat("a", 39), strings.Repeat("a", 40),
		"İorg", "Korg", "a b", "org ", "\u001forg", []any{}, []any{"x", "X"}, []any{"x", 1}, []any{nil}, 5.0, nil, true,
		map[string]any{}, strings.TrimSuffix(strings.Repeat("o,", 50), ","), func() string {
			var parts []string
			for i := range 51 {
				parts = append(parts, "o"+string(rune('a'+i%26))+string(rune('a'+i/26)))
			}
			return strings.Join(parts, ",")
		}(),
	}
}

func profileInputs() []probeRequest {
	bodies := []string{
		`{"id": 7, "login": "a"}`, `{"id": 7, "login": "a", "name": "N"}`, `{"id": 7.0, "login": "a"}`, `{"id": "7", "login": "a"}`,
		`{"id": true, "login": "a"}`, `{"id": 0, "login": "a"}`, `{"id": -1, "login": "a"}`, `{"id": 7, "login": ""}`,
		`{"id": 7, "login": "` + strings.Repeat("é", 128) + `"}`, `{"id": 7, "login": "` + strings.Repeat("é", 129) + `"}`,
		`{"id": 7, "login": "a", "name": "` + strings.Repeat("é", 256) + `"}`, `{"id": 7, "login": "a", "name": "` + strings.Repeat("é", 257) + `"}`,
		`{"id": 7, "login": "a", "name": ""}`, `{"id": 7, "login": "a", "name": 3}`, `{"id": 99999999999999999999999, "login": "a"}`,
		`{"id": 1, "id": 2, "login": "a"}`, `[]`, `"x"`, `{"id": 7, "login": "😀"}`, `{}`,
	}
	var out []probeRequest
	for _, b := range bodies {
		out = append(out, probeRequest{Op: "profile", Status: 200, Body: b})
	}
	return append(out, probeRequest{Op: "profile", Status: 404, Body: bodies[0]})
}

func loginInputs() []string {
	return []string{"octo-carol", "Octo.Carol", "__x__", "", "---", "İstanbul", "Kelvin", "ÄÖÜ", "a" + strings.Repeat("b", 40), "a-b_c", "日本"}
}

func probeRequests() []probeRequest {
	var reqs []probeRequest
	for _, root := range []string{"", "/prefix"} {
		for _, v := range redirectInputs() {
			reqs = append(reqs, probeRequest{Op: "redirect", Value: v, Root: root})
		}
	}
	for _, v := range orgInputs() {
		reqs = append(reqs, probeRequest{Op: "orgs", Value: v})
	}
	reqs = append(reqs, profileInputs()...)
	for _, l := range loginInputs() {
		reqs = append(reqs, probeRequest{Op: "base", Login: l})
	}
	return reqs
}

func goAnswer(t *testing.T, r probeRequest) any {
	switch r.Op {
	case "redirect":
		return errorText(validateRedirect(r.Value.(string), r.Root))
	case "orgs":
		orgs, err := normalizeOrgs(r.Value)
		if err != nil {
			return map[string]any{"error": errorText(err)}
		}
		out := make([]any, len(orgs))
		for i, o := range orgs {
			out[i] = o
		}
		return out
	case "profile":
		p, err := parseProfile(r.Status, []byte(r.Body))
		if err != nil {
			return nil
		}
		return []any{p.UserID, p.Login, p.DisplayName}
	case "base":
		return nameBase(r.Login)
	}
	t.Fatalf("op %s", r.Op)
	return nil
}

func TestMatchesPython(t *testing.T) {
	reqs := probeRequests()
	var cases []probeCase
	if *update {
		for i, a := range askPython(t, reqs) {
			cases = append(cases, probeCase{Request: reqs[i], Answer: a})
		}
		// One case per line keeps the file reviewable in a diff.
		var b strings.Builder
		b.WriteString("[\n")
		for i, c := range cases {
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(raw)
			if i < len(cases)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString("]\n")
		if err := os.WriteFile(vectorsFile, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		raw, err := os.ReadFile(vectorsFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &cases); err != nil {
			t.Fatal(err)
		}
		if len(cases) != len(reqs) {
			t.Fatalf("%d recorded answers for %d requests; run with -update", len(cases), len(reqs))
		}
	}
	for _, c := range cases {
		var want any
		if err := json.Unmarshal(c.Answer, &want); err != nil {
			t.Fatal(err)
		}
		got := goAnswer(t, c.Request)
		// JSON round trip so both sides have the same types.
		raw, _ := json.Marshal(got)
		var norm any
		_ = json.Unmarshal(raw, &norm)
		if !reflect.DeepEqual(norm, want) {
			t.Errorf("%s %q root %q: got %v, Python %v", c.Request.Op, c.Request.Value, c.Request.Root, norm, want)
		}
	}
}
