package e2eseed

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

func TestParsePort(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]int{"": DefaultPort, "1": 1, "4473": 4473, "65535": 65535} {
		if got, err := ParsePort(value); err != nil || got != want {
			t.Errorf("ParsePort(%q) = %d, %v", value, got, err)
		}
	}
	for _, bad := range []string{"0", "65536", "-1", "+80", "080", " 80", "80a", "1e3"} {
		if _, err := ParsePort(bad); err == nil {
			t.Errorf("ParsePort(%q) accepted", bad)
		}
	}
}

func TestScratchIsPrivateAndRemoved(t *testing.T) {
	t.Parallel()
	sc, err := NewScratch(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{sc.DataDir, sc.BackupDir, sc.TransferDir} {
		fi, err := os.Stat(dir)
		if err != nil || fi.Mode().Perm() != 0o700 || filepath.Dir(dir) != sc.Root {
			t.Fatalf("%s: %v %v", dir, fi.Mode(), err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("%s is not empty", dir)
		}
	}
	if err := sc.WriteDataFiles(map[string]string{"oidc-client-secret": "s"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(sc.DataDir, "oidc-client-secret"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("data file: %v %v", fi.Mode(), err)
	}
	if err := sc.WriteDataFiles(map[string]string{"oidc-client-secret": "again"}); err == nil {
		t.Fatal("existing data file overwritten")
	}
	for _, bad := range []string{"../x", "a/b", "..", ""} {
		if err := sc.WriteDataFiles(map[string]string{bad: "x"}); err == nil {
			t.Errorf("data file %q written", bad)
		}
	}
	if err := sc.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sc.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch left behind: %v", err)
	}
}

func TestWriteDataFilesRefusesSymlinkEscape(t *testing.T) {
	t.Parallel()
	sc, err := NewScratch(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.Symlink(outside, filepath.Join(sc.DataDir, "link")); err != nil {
		t.Skip(err)
	}
	if err := sc.WriteDataFiles(map[string]string{"link": "x"}); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file created outside the data directory")
	}
}

func TestConfig(t *testing.T) {
	t.Parallel()
	s := loadSeed(t)
	sc := &Scratch{Root: "/r", DataDir: "/r/data", BackupDir: "/r/backups", TransferDir: "/r/transfers"}
	base := []string{"PATH=/bin", "AUTOMATION_ENABLED=true", "DATA_DIR=/home/me/real-data", "REGISTRATION_ENABLED=1", "BROKEN", "=x"}
	env := s.Config(base, 4473, sc)
	want := map[string]string{
		"PATH":                    "/bin",
		"DATA_DIR":                "/r/data",
		"BACKUP_TEMP_DIR":         "/r/backups",
		"TRANSFER_TEMP_DIR":       "/r/transfers",
		"PORT":                    "4473",
		"CORS_ORIGINS":            "http://127.0.0.1:4473",
		"WEBAUTHN_ORIGIN":         "http://localhost:4473",
		"OIDC_CLIENT_SECRET_FILE": filepath.Join("/r/data", "oidc-client-secret"),
		"SECRET_KEY":              "e2e-only-secret-key",
	}
	for name, v := range want {
		if env[name] != v {
			t.Errorf("%s = %q, want %q", name, env[name], v)
		}
	}
	for _, gone := range []string{"AUTOMATION_ENABLED", "REGISTRATION_ENABLED", "BROKEN", ""} {
		if _, ok := env[gone]; ok {
			t.Errorf("%s is still set", gone)
		}
	}
	if len(env) != len(s.Environment)+4 {
		t.Errorf("config has %d variables", len(env))
	}
}

var _ client.NetDialer = (*GuardDialer)(nil)

func TestGuardDialerRefusesEverything(t *testing.T) {
	t.Parallel()
	g := loadSeed(t).Guard()
	for _, role := range []netpolicy.Role{netpolicy.RoleSSH, netpolicy.RoleSOCKS} {
		conn, err := g.DialContext(t.Context(), role, "tcp", "203.0.113.1:22")
		if conn != nil || err == nil {
			t.Fatal("guard dialed")
		}
		status, code, message := fault.Status(err)
		if status != 502 || code != fault.Unreachable || message != "E2E network guard reached" {
			t.Fatalf("status = %d %s %q", status, code, message)
		}
		if _, ok := errors.AsType[*net.OpError](err); !ok {
			t.Fatalf("cause %v is not a net.OpError", err)
		}
	}
	s := loadSeed(t)
	s.TestHooks = nil
	if s.Guard() != nil {
		t.Fatal("guard without the hook")
	}
}
