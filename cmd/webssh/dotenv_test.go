package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNeedsDotenv(t *testing.T) {
	for argv, want := range map[string]bool{
		"webssh serve": true, "webssh create-admin": true, "webssh migrate": true, "webssh backup": true,
		"webssh version": false, "webssh help": false, "webssh --help": false, "webssh healthcheck": false,
		"webssh e2e": false, "webssh": false, "/app/entrypoint.sh flask create-admin": true,
		"python /app/ldap_secret_cli.py status": false,
	} {
		if got := needsDotenv(strings.Fields(argv)); got != want {
			t.Errorf("%q: %v, want %v", argv, got, want)
		}
	}
}

func TestLoadDotenvForCommand(t *testing.T) {
	t.Setenv("WEBSSH_TEST_CMD_DOTENV", "")
	if err := os.Unsetenv("WEBSSH_TEST_CMD_DOTENV"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("WEBSSH_TEST_CMD_DOTENV=from-file\nbroken line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if !loadDotenv([]string{"webssh", "version"}, path, &stderr) || os.Getenv("WEBSSH_TEST_CMD_DOTENV") != "" {
		t.Fatal("version read .env")
	}
	if !loadDotenv([]string{"webssh", "serve"}, path, &stderr) || os.Getenv("WEBSSH_TEST_CMD_DOTENV") != "from-file" {
		t.Fatalf("serve did not read .env: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "line 2 cannot be parsed") {
		t.Errorf("stderr %q", stderr.String())
	}
	if err := os.WriteFile(path, []byte("A=\xff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if loadDotenv([]string{"webssh", "serve"}, path, &stderr) || !strings.Contains(stderr.String(), "not valid UTF-8") {
		t.Errorf("invalid .env accepted: %q", stderr.String())
	}
}
