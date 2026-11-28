package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	json "encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/admincli"
	"github.com/bifrost0x/webssh/internal/oracletest"
)

// The administrator commands are compared with the Python release:
// app/cli.py run by "flask --app start:app" and
// deployment/ldap_secret_cli.py. The Python answers are recorded in
// testdata/cli_python.json, so the comparison runs without Python;
// -update-cli records them again from the Python release
// (internal/oracletest, WEBSSH_PYTHON_ROOT). Each case runs in a fresh data
// directory, step by step, under every form: the deprecated one, which
// prints the Python program names, and the webssh one.
var updateCLI = flag.Bool("update-cli", false, "record the Python CLI answers in testdata/cli_python.json")

const cliVectors = "testdata/cli_python.json"

type cliStep struct {
	Args  []string `json:"args"`
	Stdin string   `json:"stdin,omitzero"`
	// Deviation names why Go's stdout differs on purpose; only the exit
	// code and stderr are compared then.
	Deviation string `json:"deviation,omitzero"`
	// Fix is Go's whole answer where Go corrects the Python behaviour.
	Fix *cliResult `json:"fix,omitzero"`
}

type cliCase struct {
	Name  string    `json:"name"`
	Tool  string    `json:"tool"` // "flask" or "ldap"
	Files []string  `json:"files,omitzero"`
	Steps []cliStep `json:"steps"`
	// PyEnv is set for the Python run only: what the container entrypoint
	// exports and the Go command derives itself.
	PyEnv []string `json:"py_env,omitzero"`
}

type cliResult struct {
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

const resetDeviation = "the running server ends SSH sessions only at a restart until a request queue exists (Python: within seconds)"

func cliCases() []cliCase {
	pw := func(args ...string) []string { return append([]string{"create-admin"}, args...) }
	fb := func(args ...string) []string { return append([]string{"issue-factor-bootstrap"}, args...) }
	cs := func(args ...string) []string { return append([]string{"connection-store"}, args...) }
	return []cliCase{
		{Name: "missing username", Tool: "flask", Steps: []cliStep{{Args: pw()}}},
		{Name: "unknown option", Tool: "flask", Steps: []cliStep{{Args: pw("--foo")}}},
		{Name: "short unknown option", Tool: "flask", Steps: []cliStep{{Args: pw("-x")}}},
		{Name: "option suggestion", Tool: "flask", Steps: []cliStep{{Args: pw("--usern", "x")}}},
		{Name: "missing value", Tool: "flask", Steps: []cliStep{{Args: pw("--username")}}},
		{Name: "extra argument", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "abc", "b")}}},
		{Name: "extra arguments", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "abc", "b", "c")}}},
		{Name: "double dash", Tool: "flask", Steps: []cliStep{{Args: pw("--", "--username", "x")}}},
		{Name: "help", Tool: "flask", Steps: []cliStep{{Args: pw("--help")}, {Args: []string{"reset-password", "--help"}}}},
		{Name: "help wins over missing", Tool: "flask", Steps: []cliStep{{Args: []string{"reset-password", "--help", "x"}}}},
		{Name: "help after unknown", Tool: "flask", Steps: []cliStep{{Args: pw("--help", "--bad")}}},
		{Name: "password file missing", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "admin1", "--password-file", "{tmp}/none")}}},
		{Name: "password file symlink", Tool: "flask", Files: []string{"link"}, Steps: []cliStep{{Args: pw("--username", "admin1", "--password-file", "{tmp}/link")}}},
		{Name: "password file directory", Tool: "flask", Files: []string{"dir"}, Steps: []cliStep{{Args: pw("--username", "admin1", "--password-file", "{tmp}/dir")}}},
		{Name: "password file not utf-8", Tool: "flask", Files: []string{"latin1"}, Steps: []cliStep{{Args: pw("--username", "admin1", "--password-file", "{tmp}/latin1")}}},
		{Name: "password too short", Tool: "flask", Files: []string{"short"}, Steps: []cliStep{{Args: pw("--username", "admin1", "--password-file", "{tmp}/short")}}},
		{Name: "username too short", Tool: "flask", Files: []string{"good"}, Steps: []cliStep{{Args: pw("--username", "ab", "--password-file", "{tmp}/good")}}},
		{Name: "username empty", Tool: "flask", Files: []string{"good"}, Steps: []cliStep{{Args: pw("--username=", "--password-file", "{tmp}/good")}}},
		{Name: "username characters", Tool: "flask", Files: []string{"good"}, Steps: []cliStep{{Args: pw("--username", "bad-name", "--password-file", "{tmp}/good")}}},
		{Name: "create and promote", Tool: "flask", Files: []string{"good", "crlf"}, Steps: []cliStep{
			{Args: pw("--username", "admin1", "--password-file", "{tmp}/crlf")},
			{Args: pw("--username", "admin1")},
			{Args: pw("--username", "admin1", "--password-file", "{tmp}/good")},
			{Args: pw("--username", "ADMIN1", "--password-file", "{tmp}/good")},
		}},
		{Name: "prompt", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "admin2"), Stdin: "password1\npassword1\n"}}},
		{Name: "prompt mismatch", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "admin2"), Stdin: "password1\npassword2\npassword3\r\npassword3\r\n"}}},
		{Name: "prompt empty lines", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "admin2"), Stdin: "\n\npassword1\n\npassword1\n"}}},
		{Name: "prompt end of input", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "admin2"), Stdin: "password1\n"}}},
		{Name: "prompt nothing", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "admin2")}}},
		{Name: "prompt short", Tool: "flask", Steps: []cliStep{{Args: pw("--username", "admin2"), Stdin: "short\nshort\n"}}},
		{Name: "bootstrap help", Tool: "flask", Steps: []cliStep{{Args: fb("--help")}}},
		{Name: "bootstrap missing options", Tool: "flask", Steps: []cliStep{{Args: fb()}, {Args: fb("--username", "x")}}},
		{Name: "bootstrap invalid action", Tool: "flask", Steps: []cliStep{{Args: fb("--action", "bad")}, {Args: fb("--username", "x", "--action", "bad")},
			{Args: fb("--action=bad", "--username")}}},
		{Name: "bootstrap unknown account", Tool: "flask", Steps: []cliStep{{Args: fb("--username", "nobody", "--action", "totp.enroll")}}},
		{Name: "bootstrap local account", Tool: "flask", Files: []string{"good"}, Steps: []cliStep{
			{Args: pw("--username", "admin1", "--password-file", "{tmp}/good")},
			{Args: fb("--username", "admin1", "--action", "passkey.enroll")},
		}},
		{Name: "reset unknown", Tool: "flask", Steps: []cliStep{{Args: []string{"reset-password", "--username", "nobody"}}}},
		{Name: "reset", Tool: "flask", Files: []string{"good", "other", "short"}, Steps: []cliStep{
			{Args: pw("--username", "admin1", "--password-file", "{tmp}/good")},
			{Args: []string{"reset-password", "--username", "admin1", "--password-file", "{tmp}/short"}},
			{Args: []string{"reset-password", "--username", "admin1", "--password-file", "{tmp}/other"}, Deviation: resetDeviation},
			{Args: []string{"reset-password", "--username", "admin1"}, Stdin: "password9\npassword9\n", Deviation: resetDeviation},
			{Args: []string{"reset-password", "--username", "admin1"}, Stdin: "password9\n"},
		}},
		{Name: "connection-store group", Tool: "flask", Steps: []cliStep{{Args: cs()}, {Args: cs("--help")}, {Args: cs("bogus")},
			{Args: cs("--foo")}, {Args: cs("list", "--help")}, {Args: cs("delete", "--help")}}},
		{Name: "connection-store usage", Tool: "flask", Steps: []cliStep{{Args: cs("list")}, {Args: cs("list", "--username", "x")},
			{Args: cs("list", "--username", "x", "--kind", "bad")}, {Args: cs("delete", "--username", "x", "--kind", "profiles")},
			{Args: cs("list", "--username", "x", "--kind", "profiles", "--confirm-offline=yes")}}},
		{Name: "connection-store offline", Tool: "flask", Steps: []cliStep{{Args: cs("list", "--username", "x", "--kind", "profiles")},
			{Args: cs("delete", "--username", "x", "--kind", "jump-hosts", "--selector", "s")}}},
		{Name: "connection-store records", Tool: "flask", Files: []string{"good"}, Steps: []cliStep{
			{Args: pw("--username", "admin1", "--password-file", "{tmp}/good")},
			{Args: cs("list", "--username", "nobody", "--kind", "profiles", "--confirm-offline")},
			{Args: cs("list", "--username", "admin1", "--kind", "profiles", "--confirm-offline")},
			{Args: cs("list", "--username", "admin1", "--kind", "jump-hosts", "--confirm-offline")},
			{Args: cs("list", "--username", "admin1", "--kind", "socks-proxies", "--confirm-offline")},
			{Args: cs("delete", "--username", "admin1", "--kind", "profiles", "--selector", "r1:0:"+strings.Repeat("0", 64), "--confirm-offline")},
			{Args: cs("delete", "--username", "admin1", "--kind", "socks-proxies", "--selector", "x", "--confirm-offline")},
			{Args: cs("delete", "--username", "ADMIN1", "--kind", "socks-proxies", "--selector", "x", "--confirm-offline")},
		}},
		{Name: "rotate usage", Tool: "flask", Steps: []cliStep{{Args: []string{"rotate-secret-key", "--help"}},
			{Args: []string{"rotate-secret-key", "--confirm-offline=yes"}}, {Args: []string{"rotate-secret-key", "extra"}},
			{Args: []string{"rotate-secret-key", "--bogus"}}, {Args: []string{"rotate-secret-key"}}}},
		{Name: "rotate environment secret", Tool: "flask", PyEnv: []string{"WEBSSH_SECRET_KEY_SOURCE=environment"},
			Steps: []cliStep{{Args: []string{"rotate-secret-key", "--confirm-offline"}}}},
		{Name: "ldap no command", Tool: "ldap", Steps: []cliStep{{Args: []string{"--secret-dir", "{tmp}/s"}}}},
		{Name: "ldap help", Tool: "ldap", Steps: []cliStep{{Args: []string{"--help"}}, {Args: []string{"--secret-dir", "{tmp}/s", "set-password", "--help"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca", "--help"}}, {Args: []string{"--secret-dir", "{tmp}/s", "remove", "--help"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "status", "--help"}}}},
		{Name: "ldap unknown command", Tool: "ldap", Steps: []cliStep{{Args: []string{"--secret-dir", "{tmp}/s", "bogus"}}}},
		{Name: "ldap unknown group option", Tool: "ldap", Steps: []cliStep{{Args: []string{"--secret", "x", "status"}}}},
		{Name: "ldap status and password", Tool: "ldap", Steps: []cliStep{
			{Args: []string{"--secret-dir", "{tmp}/s", "status"}},
			{Args: []string{"--secret-dir={tmp}/s", "set-password", "--stdin"}, Stdin: "bind secret\r\n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "status"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "set-password"}, Stdin: "one\ntwo\n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "set-password"}, Stdin: "one\none\n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "set-password"}, Stdin: "one\n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "set-password"}, Stdin: "\n\n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "set-password", "--stdin"}, Stdin: "\n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "set-password", "--stdin"}, Stdin: "a\x00b"},
			{Args: []string{"--secret-dir", "{tmp}/s", "set-password", "--stdin=yes"}},
		}},
		{Name: "ldap ca", Tool: "ldap", Files: []string{"ca.pem", "garbage.pem"}, Steps: []cliStep{
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca", "{tmp}/none.pem"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca", "--stdin", "{tmp}/ca.pem"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca", "{tmp}/garbage.pem"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca", "--stdin"}, Stdin: "not pem"},
			// Python installs an empty bundle, after which every LDAP TLS
			// connection fails; Go refuses it.
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca", "--stdin"}, Stdin: "",
				Fix: &cliResult{Code: 1, Stderr: "Error: CA bundle is not valid PEM certificate data\n"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca", "{tmp}/ca.pem"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "install-ca", "{tmp}/ca.pem", "{tmp}/ca.pem"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "status"}},
		}},
		{Name: "ldap remove", Tool: "ldap", Steps: []cliStep{
			{Args: []string{"--secret-dir", "{tmp}/s", "set-password", "--stdin"}, Stdin: "bind secret"},
			{Args: []string{"--secret-dir", "{tmp}/s", "remove"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "remove"}, Stdin: "maybe\nn\n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "remove"}, Stdin: "\n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "status"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "remove"}, Stdin: " YES \n"},
			{Args: []string{"--secret-dir", "{tmp}/s", "status"}},
			{Args: []string{"--secret-dir", "{tmp}/s", "remove", "--yes"}},
		}},
	}
}

// writeCaseFiles creates the files a case names in dir.
func writeCaseFiles(t *testing.T, dir string, names []string, ca []byte) {
	t.Helper()
	for _, n := range names {
		p := filepath.Join(dir, n)
		var err error
		switch n {
		case "link":
			if err = os.WriteFile(filepath.Join(dir, "target"), []byte("password1\n"), 0o600); err == nil {
				err = os.Symlink(filepath.Join(dir, "target"), p)
			}
		case "dir":
			err = os.Mkdir(p, 0o700)
		case "latin1":
			err = os.WriteFile(p, []byte("passw\xf6rd1\n"), 0o600)
		case "short":
			err = os.WriteFile(p, []byte("short\n"), 0o600)
		case "good":
			err = os.WriteFile(p, []byte("password1\n"), 0o600)
		case "crlf":
			err = os.WriteFile(p, []byte("password1\r\n"), 0o600)
		case "other":
			err = os.WriteFile(p, []byte("password2"), 0o600)
		case "ca.pem":
			err = os.WriteFile(p, ca, 0o600)
		case "garbage.pem":
			err = os.WriteFile(p, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600)
		default:
			t.Fatalf("unknown case file %q", n)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func testCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ldap ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func substitute(args []string, tmp string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.ReplaceAll(a, "{tmp}", tmp)
	}
	return out
}

// normalize drops what is not part of the command's answer: the JSON log
// lines and the CORS notice the Flask application prints at import, the
// Python warning of getpass, the Go deprecation notice, and the
// temporary directory.
func normalize(s, tmp string) string {
	var keep []string
	for line := range strings.SplitAfterSeq(s, "\n") {
		switch {
		case strings.HasPrefix(line, `{"timestamp"`), strings.HasPrefix(line, "INFO: CORS_ORIGINS"),
			strings.Contains(line, "GetPassWarning"), strings.HasPrefix(line, "  passwd = fallback_getpass"),
			strings.HasPrefix(line, "webssh: the form "):
			continue
		}
		keep = append(keep, line)
	}
	return strings.ReplaceAll(strings.Join(keep, ""), tmp, "{tmp}")
}

func pythonCLI(t *testing.T, c cliCase, step cliStep, tmp, dataDir string) cliResult {
	t.Helper()
	rel := oracletest.Require(t)
	root, venv := rel.Root, filepath.Dir(rel.Python)
	var cmd *exec.Cmd
	if c.Tool == "flask" {
		cmd = exec.CommandContext(t.Context(), filepath.Join(venv, "flask"), append([]string{"--app", "start:app"}, substitute(step.Args, tmp)...)...) // #nosec G204 -- test oracle
	} else {
		cmd = exec.CommandContext(t.Context(), filepath.Join(venv, "python"), append([]string{filepath.Join(root, "deployment", "ldap_secret_cli.py")}, substitute(step.Args, tmp)...)...) // #nosec G204 -- test oracle
	}
	cmd.Dir = root
	cmd.Env = append(append(os.Environ(), "DATA_DIR="+dataDir, "SECRET_KEY="+testSecret, "PYTHONWARNINGS=ignore"), c.PyEnv...)
	cmd.Stdin = strings.NewReader(step.Stdin)
	// A new session has no controlling terminal: getpass reads standard
	// input, as under "docker compose exec -T".
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return cliResult{Code: code, Stdout: normalize(out.String(), tmp), Stderr: normalize(errOut.String(), tmp)}
}

// goForms are the argument vectors that run step under Go, with the
// program name Python's output would have under that form.
func goForms(tool string, args []string) map[string][]string {
	if tool == "flask" {
		return map[string][]string{
			"flask":  append([]string{"/app/entrypoint.sh", "flask", "--app", "start:app"}, args...),
			"webssh": append([]string{"/app/webssh"}, args...),
		}
	}
	return map[string][]string{
		"ldap_secret_cli.py": append([]string{"/usr/local/bin/python", ldapHelperPath}, args...),
		"webssh ldap-secret": append([]string{"/app/webssh", "ldap-secret"}, args...),
	}
}

func goCLI(t *testing.T, argv []string, stdin, tmp string) cliResult {
	t.Helper()
	var out, errOut bytes.Buffer
	code := dispatch(t.Context(), argv, streams{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errOut})
	return cliResult{Code: code, Stdout: normalize(out.String(), tmp), Stderr: normalize(errOut.String(), tmp)}
}

// TestCLIMatchesPython must not run in parallel: it sets DATA_DIR and
// SECRET_KEY for the in-process commands.
func TestCLIMatchesPython(t *testing.T) {
	terminalOpener = func() (admincli.Terminal, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { terminalOpener = admincli.OpenTerminal })
	t.Setenv("SECRET_KEY", testSecret)
	ca := testCA(t)
	recorded := map[string][]cliResult{}
	if !*updateCLI {
		raw, err := os.ReadFile(cliVectors)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &recorded); err != nil {
			t.Fatal(err)
		}
	} else {
		oracletest.Require(t)
	}
	for _, c := range cliCases() {
		t.Run(c.Name, func(t *testing.T) {
			if *updateCLI {
				tmp := t.TempDir()
				writeCaseFiles(t, tmp, c.Files, ca)
				for _, step := range c.Steps {
					recorded[c.Name] = append(recorded[c.Name], pythonCLI(t, c, step, tmp, filepath.Join(tmp, "data")))
				}
			}
			want := recorded[c.Name]
			if len(want) != len(c.Steps) {
				t.Fatalf("recorded %d results for %d steps; run with -update-cli", len(want), len(c.Steps))
			}
			pyProg := map[string]string{"flask": "flask", "ldap": "ldap_secret_cli.py"}[c.Tool]
			for prog := range goForms(c.Tool, nil) {
				t.Run(prog, func(t *testing.T) {
					tmp := t.TempDir()
					writeCaseFiles(t, tmp, c.Files, ca)
					t.Setenv("DATA_DIR", filepath.Join(tmp, "data"))
					for i, step := range c.Steps {
						got := goCLI(t, goForms(c.Tool, substitute(step.Args, tmp))[prog], step.Stdin, tmp)
						w := want[i]
						if step.Fix != nil {
							w = *step.Fix
						}
						w.Stdout = renameProg(w.Stdout, pyProg, prog)
						w.Stderr = renameProg(w.Stderr, pyProg, prog)
						if got.Code != w.Code || got.Stderr != w.Stderr || (step.Deviation == "" && got.Stdout != w.Stdout) {
							t.Errorf("step %d %q:\n got %+v\nwant %+v", i, step.Args, got, w)
						}
					}
				})
			}
		})
	}
	if *updateCLI {
		raw, err := json.Marshal(recorded, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cliVectors, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// renameProg replaces the Python program name in usage lines.
func renameProg(s, from, to string) string {
	if from == to {
		return s
	}
	s = strings.ReplaceAll(s, "Usage: "+from+" ", "Usage: "+to+" ")
	return strings.ReplaceAll(s, "Try '"+from+" ", "Try '"+to+" ")
}
