package config

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// entryCase prepares a directory tree under root and names the
// environment for the startup rules of entrypoint.sh.
type entryCase struct {
	name  string
	setup func(t *testing.T, root string)
	env   func(root string) map[string]string
	// want, when not nil, is the expected outcome; "<generated>" stands
	// for a new 64-digit hex secret.
	want *entryResult
}

type entryResult struct {
	failed            bool
	dataDir, secret   string
	source            SecretSource
	dataDirFromRootFn func(root string) string
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func dataEnv(sub string, extra ...string) func(root string) map[string]string {
	return func(root string) map[string]string {
		env := map[string]string{"DATA_DIR": root + "/" + sub}
		for i := 0; i+1 < len(extra); i += 2 {
			env[extra[i]] = extra[i+1]
		}
		return env
	}
}

func ok(sub, secret string, source SecretSource) *entryResult {
	return &entryResult{secret: secret, source: source, dataDirFromRootFn: func(root string) string { return filepath.Join(root, sub) }}
}

var failed = &entryResult{failed: true}

func entryCases() []entryCase {
	file := func(content string) func(t *testing.T, root string) {
		return func(t *testing.T, root string) { writeFile(t, filepath.Join(root, "d", "secret_key"), content, 0o600) }
	}
	return []entryCase{
		{name: "environment wins", env: dataEnv("d", "SECRET_KEY", " my secret "), setup: file("other\n"), want: ok("d", " my secret ", SecretFromEnvironment)},
		{name: "placeholder uses file", env: dataEnv("d", "SECRET_KEY", "changeme"), setup: file("from-file\n"), want: ok("d", "from-file", SecretFromFile)},
		{name: "placeholder with spaces and case", env: dataEnv("d", "SECRET_KEY", " Change\tMe "), setup: file("from-file\n"), want: ok("d", "from-file", SecretFromFile)},
		{name: "template placeholder", env: dataEnv("d", "SECRET_KEY", "<YOUR-SECRET-KEY>"), setup: file("f\n"), want: ok("d", "f", SecretFromFile)},
		{name: "non-breaking space is not removed", env: dataEnv("d", "SECRET_KEY", " changeme"), setup: file("f\n"), want: ok("d", " changeme", SecretFromEnvironment)},
		{name: "CRLF keeps CR", env: dataEnv("d"), setup: file("key\r\n"), want: ok("d", "key\r", SecretFromFile)},
		{name: "all trailing LF removed", env: dataEnv("d"), setup: file("key\n\n\n"), want: ok("d", "key", SecretFromFile)},
		{name: "inner LF kept", env: dataEnv("d"), setup: file("a\nb\n"), want: ok("d", "a\nb", SecretFromFile)},
		{name: "NUL bytes dropped", env: dataEnv("d"), setup: file("ab\x00cd\n"), want: ok("d", "abcd", SecretFromFile)},
		{name: "empty file exports empty secret", env: dataEnv("d"), setup: file(""), want: ok("d", "", SecretFromFile)},
		{name: "generated", env: dataEnv("d"), want: ok("d", "<generated>", SecretFromFile)},
		{name: "generated in new directory", env: dataEnv("new/deeper"), want: ok("new/deeper", "<generated>", SecretFromFile)},
		{name: "relative data dir", env: func(string) map[string]string { return map[string]string{"DATA_DIR": "data"} }, want: failed},
		{name: "trailing slash and dots", env: dataEnv("x/./y/../d/"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "x", "d", "secret_key"), "k\n", 0o600)
		}, want: ok("x/d", "k", SecretFromFile)},
		{name: "double slashes", env: dataEnv("/d//"), setup: file("k\n"), want: ok("d", "k", SecretFromFile)},
		{name: "symlinked data dir", env: dataEnv("link"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "real", "secret_key"), "k\n", 0o600)
			symlink(t, filepath.Join(root, "real"), filepath.Join(root, "link"))
		}, want: ok("real", "k", SecretFromFile)},
		{name: "relative symlink", env: dataEnv("link"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "real", "secret_key"), "k\n", 0o600)
			symlink(t, "real", filepath.Join(root, "link"))
		}, want: ok("real", "k", SecretFromFile)},
		{name: "dangling symlink is created", env: dataEnv("link"), setup: func(t *testing.T, root string) {
			symlink(t, filepath.Join(root, "target"), filepath.Join(root, "link"))
		}, want: ok("target", "<generated>", SecretFromFile)},
		{name: "symlink loop", env: dataEnv("a/data"), setup: func(t *testing.T, root string) {
			symlink(t, filepath.Join(root, "b"), filepath.Join(root, "a"))
			symlink(t, filepath.Join(root, "a"), filepath.Join(root, "b"))
		}, want: failed},
		{name: "trailing newline in name", env: func(root string) map[string]string {
			return map[string]string{"DATA_DIR": filepath.Join(root, "nl") + "\n"}
		}, want: ok("nl", "<generated>", SecretFromFile)},
		{name: "secret file is a directory", env: dataEnv("d"), setup: func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, "d", "secret_key"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, want: failed},
		{name: "secret file is a symlink", env: dataEnv("d"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "elsewhere"), "linked\n", 0o600)
			if err := os.MkdirAll(filepath.Join(root, "d"), 0o700); err != nil {
				t.Fatal(err)
			}
			symlink(t, filepath.Join(root, "elsewhere"), filepath.Join(root, "d", "secret_key"))
		}, want: ok("d", "linked", SecretFromFile)},
		{name: "unreadable secret file", env: dataEnv("d"), setup: func(t *testing.T, root string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads every file")
			}
			writeFile(t, filepath.Join(root, "d", "secret_key"), "k\n", 0o000)
		}, want: failed},
		{name: "legacy secret without new file", env: dataEnv("d"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "legacy", "secret_key"), "old\n", 0o600)
		}, want: failed},
		{name: "legacy secret differs", env: dataEnv("d"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "legacy", "secret_key"), "old\n", 0o600)
			writeFile(t, filepath.Join(root, "d", "secret_key"), "old", 0o600)
		}, want: failed},
		{name: "legacy secret equal", env: dataEnv("d"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "legacy", "secret_key"), "same\n", 0o600)
			writeFile(t, filepath.Join(root, "d", "secret_key"), "same\n", 0o600)
		}, want: ok("d", "same", SecretFromFile)},
		{name: "legacy ignored with environment secret", env: dataEnv("d", "SECRET_KEY", "explicit-secret"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "legacy", "secret_key"), "old\n", 0o600)
		}, want: ok("d", "explicit-secret", SecretFromEnvironment)},
		{name: "legacy is the data dir", env: dataEnv("legacy"), setup: func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "legacy", "secret_key"), "same\n", 0o600)
		}, want: ok("legacy", "same", SecretFromFile)},
	}
}

var hexSecret = regexp.MustCompile(`^[0-9a-f]{64}$`)

// prepareLikeEntrypoint creates the directories entrypoint.sh creates;
// internal/platform does this in the Go release.
func prepareLikeEntrypoint(dataDir string) error {
	for _, d := range []string{dataDir, filepath.Join(dataDir, "logs"), filepath.Join(dataDir, "keys")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func runGoEntrypoint(root string, env map[string]string) (entryResult, error) {
	lookup := lookupMap(env)
	dataDir, err := resolveDataDir(osFS{}, lookup)
	if err != nil {
		return entryResult{}, err
	}
	if err := prepareLikeEntrypoint(dataDir); err != nil {
		return entryResult{}, err
	}
	res, _, err := resolveSecretKey(osFS{}, createSecretFile, filepath.Join(root, "legacy", "secret_key"), dataDir, lookup)
	if err != nil {
		return entryResult{}, err
	}
	return entryResult{dataDir: dataDir, secret: string(res.Key.value), source: res.Source}, nil
}

func checkEntry(t *testing.T, root string, want entryResult, got entryResult, err error) {
	t.Helper()
	if want.failed {
		if err == nil {
			t.Fatalf("started with %+v, want a failure", got)
		}
		return
	}
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if wantDir := want.dataDirFromRootFn(root); got.dataDir != wantDir {
		t.Errorf("DATA_DIR %q, want %q", got.dataDir, wantDir)
	}
	if got.source != want.source {
		t.Errorf("source %q, want %q", got.source, want.source)
	}
	if want.secret == "<generated>" {
		if !hexSecret.MatchString(got.secret) {
			t.Errorf("generated secret %q is not 64 hex digits", got.secret)
		}
		data, err := os.ReadFile(filepath.Join(got.dataDir, "secret_key"))
		if err != nil || string(data) != got.secret+"\n" {
			t.Errorf("secret file %q, %v; want the secret and a line feed", data, err)
		}
		if info, err := os.Stat(filepath.Join(got.dataDir, "secret_key")); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("secret file: %v, %v; want mode 0600", info, err)
		}
	} else if got.secret != want.secret {
		t.Errorf("secret %q, want %q", got.secret, want.secret)
	}
}

// TestEntrypointRules pins the DATA_DIR and SECRET_KEY rules of
// entrypoint.sh (invariant I-08, migration spec A02).
func TestEntrypointRules(t *testing.T) {
	for _, tc := range entryCases() {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, root)
			}
			got, err := runGoEntrypoint(root, tc.env(root))
			checkEntry(t, root, *tc.want, got, err)
		})
	}
}

// TestEntrypointDifferential runs the real entrypoint.sh of the Python
// release on the same trees and compares DATA_DIR, SECRET_KEY and
// WEBSSH_SECRET_KEY_SOURCE as it hands them to the application.
func TestEntrypointDifferential(t *testing.T) {
	python, err := filepath.Abs(pythonPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(python); err != nil {
		t.Skip("no Python virtual environment")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	script, err := os.ReadFile(filepath.Join(repoRoot, "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	symlink(t, python, filepath.Join(bin, "python"))
	for _, tc := range entryCases() {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, root)
			}
			legacy := filepath.Join(root, "legacy", "secret_key")
			patched := bytes.ReplaceAll(script, []byte(legacySecretKeyFile), []byte(legacy))
			entry := filepath.Join(t.TempDir(), "entrypoint.sh")
			writeFile(t, entry, string(patched), 0o700)
			env := tc.env(root)
			result := filepath.Join(t.TempDir(), "result")
			cmd := exec.CommandContext(t.Context(), bash, entry, "sh", "-c", `printf '%s\0%s\0%s\0' "$DATA_DIR" "$SECRET_KEY" "$WEBSSH_SECRET_KEY_SOURCE" > "$F1_RESULT"`)
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + root, "F1_RESULT=" + result}
			for k, v := range env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			runErr := cmd.Run()
			var py entryResult
			if runErr != nil {
				if _, ok := errors.AsType[*exec.ExitError](runErr); !ok {
					t.Fatal(runErr)
				}
				py.failed = true
			} else {
				out, err := os.ReadFile(result)
				if err != nil {
					t.Fatal(err)
				}
				parts := strings.Split(string(out), "\x00")
				if len(parts) != 4 {
					t.Fatalf("entrypoint output %q", out)
				}
				py = entryResult{dataDir: parts[0], secret: parts[1], source: SecretSource(parts[2])}
			}
			if py.failed != tc.want.failed {
				t.Fatalf("Python failed=%v (%s), table says %v", py.failed, stderr.String(), tc.want.failed)
			}
			if !py.failed {
				want := *tc.want
				checkEntry(t, root, want, py, nil)
				// Go on a fresh copy of the same tree.
				root2 := t.TempDir()
				if tc.setup != nil {
					tc.setup(t, root2)
				}
				got, err := runGoEntrypoint(root2, tc.env(root2))
				checkEntry(t, root2, want, got, err)
			}
		})
	}
}
