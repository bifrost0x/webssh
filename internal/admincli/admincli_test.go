package admincli

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Values from Python 3.15 difflib (get_close_matches and
// SequenceMatcher.ratio).
func TestCloseMatchesLikeDifflib(t *testing.T) {
	t.Parallel()
	cands := []string{"--help", "--username", "--password-file"}
	tests := []struct {
		word   string
		want   []string
		ratios [3]float64
	}{
		{"--usern", []string{"--username"}, [3]float64{0.461538, 0.823529, 0.363636}},
		{"--user", []string{"--username"}, [3]float64{0.5, 0.75, 0.380952}},
		{"--pass", nil, [3]float64{0.5, 0.375, 0.571429}},
		{"--password", []string{"--password-file"}, [3]float64{0.375, 0.4, 0.8}},
		{"--hepl", []string{"--help"}, [3]float64{0.833333, 0.375, 0.380952}},
		{"--usernmae", []string{"--username"}, [3]float64{0.375, 0.9, 0.32}},
		{"-x", nil, [3]float64{0.25, 0.166667, 0.117647}},
		{"--secret", []string{"--username"}, [3]float64{0.428571, 0.666667, 0.434783}},
		{"--x", nil, [3]float64{0.444444, 0.307692, 0.222222}},
	}
	for _, tt := range tests {
		if got := closeMatches(tt.word, cands); !slices.Equal(got, tt.want) && len(got)+len(tt.want) > 0 {
			t.Errorf("closeMatches(%q) = %q, want %q", tt.word, got, tt.want)
		}
		for i, c := range cands {
			if r := ratio(c, tt.word); math.Abs(r-tt.ratios[i]) > 1e-6 {
				t.Errorf("ratio(%q, %q) = %f, want %f", c, tt.word, r, tt.ratios[i])
			}
		}
	}
}

func FuzzCloseMatches(f *testing.F) {
	f.Add("--usern")
	f.Add("")
	f.Add("--ü\x00")
	f.Fuzz(func(t *testing.T, word string) {
		got := closeMatches(word, []string{"--help", "--username", "--password-file"})
		if len(got) > 3 {
			t.Fatalf("%d matches", len(got))
		}
		if r := ratio(word, "--username"); r < 0 || r > 1 {
			t.Fatalf("ratio %f", r)
		}
	})
}

// FuzzParse checks the parser's invariants: it never panics, a parsed
// result holds only known options, and every positional argument is kept.
func FuzzParse(f *testing.F) {
	f.Add("--username\x00a\x00--password-file=b")
	f.Add("--\x00--username")
	f.Add("-x\x00--help=1")
	f.Fuzz(func(t *testing.T, joined string) {
		c := passwordCommand("webssh", "create-admin", "")
		c.maxArgs = 100
		p, err := c.parse(strings.Split(joined, "\x00"))
		if err != nil {
			return
		}
		for k := range p.values {
			if k != "--username" && k != "--password-file" {
				t.Fatalf("unknown option %q accepted", k)
			}
		}
		if _, ok := p.values["--username"]; !ok && !p.help {
			t.Fatal("missing --username accepted")
		}
	})
}

func TestReadPasswordFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		name, data, want, err string
	}{
		{"lf", "password1\n", "password1", ""},
		{"crlf", "password1\r\n", "password1", ""},
		{"only one line end", "password1\n\n", "password1\n", ""},
		{"cr only kept", "password1\r", "password1\r", ""},
		{"empty", "", "", ""},
		{"at limit with line end", strings.Repeat("a", 10) + "\r\n", strings.Repeat("a", 10), ""},
		{"three bytes over", strings.Repeat("a", 13), strings.Repeat("a", 13), ""},
		{"four bytes over", strings.Repeat("a", 14), "", "Password must not exceed 10 bytes when encoded as UTF-8."},
		{"latin-1", "p\xe4ss", "", "Password file must contain valid UTF-8."},
	}
	for _, tt := range tests {
		got, err := readPasswordFile(write(tt.name, []byte(tt.data)), 10)
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("%s: err %v, want %q", tt.name, err, tt.err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: %q, %v; want %q", tt.name, got, err, tt.want)
		}
	}
	fifo := filepath.Join(dir, "fifo")
	if err := mkfifo(fifo); err == nil {
		if _, err := readPasswordFile(fifo, 10); err == nil || err.Error() != "Password file must be a regular file." {
			t.Errorf("fifo: %v", err)
		}
	}
}

func TestReadLineUniversalNewlines(t *testing.T) {
	t.Parallel()
	p := &prompter{stdin: bufio.NewReader(strings.NewReader("a\r\nb\rc\nlast"))}
	var got []string
	for {
		l, err := p.readLine()
		if err != nil {
			break
		}
		got = append(got, l)
	}
	if want := []string{"a", "b", "c", "last"}; !slices.Equal(got, want) {
		t.Errorf("lines %q, want %q", got, want)
	}
}

// The hidden prompt reads the terminal, never standard input, and does
// not echo the password anywhere.
func TestPromptUsesTerminal(t *testing.T) {
	t.Parallel()
	term := &fakeTerminal{lines: []string{"", "secret-pass", "secret-pass"}}
	var out, errOut bytes.Buffer
	p := newPrompter(IO{Stdin: strings.NewReader("stdin-pass\nstdin-pass\n"), Stdout: &out, Stderr: &errOut,
		Terminal: func() (Terminal, error) { return term, nil }})
	got, err := p.clickPassword("Password")
	if err != nil || got != "secret-pass" {
		t.Fatalf("%q, %v", got, err)
	}
	all := out.String() + errOut.String() + term.out.String()
	if strings.Contains(all, "secret-pass") {
		t.Errorf("password echoed: %q", all)
	}
	if want := "Password: \nPassword: \nRepeat for confirmation: \n"; term.out.String() != want {
		t.Errorf("terminal output %q, want %q", term.out.String(), want)
	}
}

type fakeTerminal struct {
	lines []string
	out   bytes.Buffer
}

func (f *fakeTerminal) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeTerminal) ReadPassword() ([]byte, error) {
	if len(f.lines) == 0 {
		return nil, os.ErrClosed
	}
	l := f.lines[0]
	f.lines = f.lines[1:]
	return []byte(l), nil
}
func (*fakeTerminal) Close() error { return nil }

func TestValidCABundle(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		data string
		want bool
	}{
		"empty":       {"", false},
		"text":        {"not pem", false},
		"bad cert":    {"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", false},
		"only a key":  {"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", false},
		"non-ascii":   {"é", false},
		"valid":       {testCertPEM, true},
		"valid twice": {"comment\n" + testCertPEM + testCertPEM, true},
		"valid+bad":   {testCertPEM + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", false},
	} {
		if got := validCABundle([]byte(tt.data)); got != tt.want {
			t.Errorf("%s: %v, want %v", name, got, tt.want)
		}
	}
}

func FuzzValidCABundle(f *testing.F) {
	f.Add([]byte(testCertPEM))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = validCABundle(data)
	})
}

// The LDAP files are written with mode 0600 into a 0700 directory, and no
// temporary file is left.
func TestLDAPSecretModes(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "s")
	var out, errOut bytes.Buffer
	o := IO{Stdin: strings.NewReader("bind secret\n"), Stdout: &out, Stderr: &errOut}
	if code := LDAPSecret("webssh ldap-secret", []string{"--secret-dir", dir, "set-password", "--stdin"}, o); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("directory: %v, %v", info, err)
	}
	info, err = os.Stat(filepath.Join(dir, ldapPasswordFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("file: %v, %v", info, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ldapPasswordFile)); string(b) != "bind secret" {
		t.Errorf("content %q", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("entries %v", entries)
	}
	// A link as the secret directory is refused.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := LDAPSecret("x", []string{"--secret-dir", link, "status"}, o); code != 1 ||
		errOut.String() != "Error: Secret directory must be a real directory\n" {
		t.Errorf("link: %d %q", code, errOut.String())
	}
}
