package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/admincli"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

const testSecret = "cli-oracle-secret-0123456789abcdef0123456789"

// adminEnv prepares a fresh data directory for the in-process commands.
// The tests that use it set environment variables and do not run in
// parallel.
func adminEnv(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SECRET_KEY", testSecret)
	t.Setenv("BACKUP_TEMP_DIR", filepath.Join(t.TempDir(), "ops"))
	terminalOpener = func() (admincli.Terminal, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { terminalOpener = admincli.OpenTerminal })
	return dir
}

func runIn(t *testing.T, stdin string, argv ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := dispatch(t.Context(), argv, streams{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errOut})
	return code, out.String(), errOut.String()
}

// reset-password changes the password, raises the account's generation
// and ends every session of the account in one transaction.
func TestResetPasswordEndsSessions(t *testing.T) {
	dir := adminEnv(t)
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatalf("create-admin: %s", e)
	}
	ctx := t.Context()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	g, err := openGoData(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := g.accounts.ByUsername(ctx, "admin1")
	if err != nil || !acc.IsAdmin {
		t.Fatalf("%+v, %v", acc, err)
	}
	_, token, err := g.sessions.Issue(ctx, session.IssueRequest{UserID: acc.ID, Generation: acc.AuthGeneration,
		PrimaryMethod: "password", Methods: []string{"password"}, Assurance: session.Basic})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	code, out, e := runIn(t, "password2\npassword2\n", "/app/entrypoint.sh", "flask", "--app", "start:app", "reset-password", "--username", "admin1")
	if code != 0 || !strings.Contains(out, "Password reset for admin1.") {
		t.Fatalf("reset: %d %q %q", code, out, e)
	}
	if strings.Contains(out+e, "password2") {
		t.Error("the password was echoed")
	}
	g, err = openGoData(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if _, err := g.sessions.Validate(ctx, token); err == nil {
		t.Error("the session survived the reset")
	}
	after, _ := g.accounts.ByUsername(ctx, "admin1")
	if after.AuthGeneration <= acc.AuthGeneration {
		t.Errorf("generation %d -> %d", acc.AuthGeneration, after.AuthGeneration)
	}
	for pw, want := range map[string]bool{"password1": false, "password2": true} {
		if ok, err := g.local.Matches(ctx, acc.ID, pw); err != nil || ok != want {
			t.Errorf("Matches(%s) = %v, %v", pw, ok, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "logs", "security_audit.log")); !strings.Contains(string(b), "PASSWORD_RESET_CLI | user=admin1") {
		t.Errorf("audit log: %s", b)
	}
}

// Managed accounts are neither promoted nor reset.
func TestAdminCommandsRefuseManagedAccounts(t *testing.T) {
	adminEnv(t)
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatal(e)
	}
	cfg, _ := loadConfig()
	g, err := openGoData(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = g.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO accounts_users (id, username, incarnation, history_generation, managed_by)
			VALUES (50, 'dir1', 'x', 'x', ?), (51, 'gh1', 'y', 'y', ?)`, string(accounts.ManagedLDAP), string(accounts.ManagedGitHub))
		return err
	})
	if err := errors.Join(err, g.Close()); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ args, want string }{
		{"create-admin --username dir1", "Error: LDAP-managed accounts cannot be administrators.\n"},
		{"create-admin --username gh1", "Error: GitHub-managed accounts cannot be administrators.\n"},
		{"reset-password --username dir1", "Error: The password of an LDAP-managed account is set in the directory.\n"},
		{"reset-password --username gh1", "Error: GitHub-managed accounts sign in through GitHub and have no local password.\n"},
	} {
		code, _, e := runIn(t, "password1\npassword1\n", append([]string{"webssh"}, strings.Fields(tt.args)...)...)
		if code != 1 || e != tt.want {
			t.Errorf("%s: %d %q", tt.args, code, e)
		}
	}
}

// The commands never migrate: before the first migration they refuse and
// leave the legacy data alone.
func TestAdminCommandsRefuseBeforeMigration(t *testing.T) {
	dir := adminEnv(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.db"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, e := runIn(t, "", "webssh", "reset-password", "--username", "admin1")
	if code != 1 || !strings.Contains(e, "has not been migrated yet") {
		t.Fatalf("%d %q", code, e)
	}
	if _, err := os.Stat(filepath.Join(dir, "go", "webssh.db")); !os.IsNotExist(err) {
		t.Errorf("a Go database was created: %v", err)
	}
}

// While a server holds the Go lock, the commands work on the same
// database, as the Python CLI did beside the running application.
func TestAdminCommandsBesideRunningServer(t *testing.T) {
	adminEnv(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatal(e)
	}
	o, err := migrationOptions(cfg, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	st, err := legacy.Start(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	code, out, e := runIn(t, "", "webssh", "create-admin", "--username", "admin1")
	if code != 0 || out != "Administrator ready: admin1\n" {
		t.Fatalf("%d %q %q", code, out, e)
	}
	// migrate --replace needs the service stopped.
	if code, _, e := runIn(t, "", "webssh", "migrate", "--dry-run"); code != 1 || !strings.Contains(e, "another WebSSH process") {
		t.Errorf("dry run beside a server: %d %q", code, e)
	}
}

func TestPythonShim(t *testing.T) {
	t.Parallel()
	for _, argv := range [][]string{
		{"python"},
		{"python", "-c", "print(1)"},
		{"/usr/local/bin/python3", "/app/start.py"},
		{"python", "deployment/ldap_secret_cli.py", "status"},
	} {
		code, out, e := runArgs(t, argv...)
		if code != 2 || out != "" || !strings.Contains(e, "has no Python") {
			t.Errorf("%q: %d %q %q", argv, code, out, e)
		}
	}
	code, out, e := runArgs(t, "python", ldapHelperPath, "--help")
	if code != 0 || !strings.HasPrefix(out, "Usage: ldap_secret_cli.py [OPTIONS] COMMAND") || !strings.Contains(e, "deprecated") {
		t.Errorf("help: %d %q %q", code, out, e)
	}
}

func TestMigrateAndPurgeUsage(t *testing.T) {
	adminEnv(t)
	for _, args := range [][]string{
		{"migrate"}, {"migrate", "--dry-run", "--replace"}, {"migrate", "--bogus"}, {"migrate", "--dry-run", "x"},
		{"legacy"}, {"legacy", "remove"}, {"legacy", "purge", "--skip-backup", "--backup-to", "/x"}, {"legacy", "purge", "x"},
	} {
		if code, _, _ := runIn(t, "", append([]string{"webssh"}, args...)...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	// Without confirmation nothing happens.
	if code, _, e := runIn(t, "n\n", "webssh", "legacy", "purge"); code != 1 || e != "Aborted!\n" {
		t.Errorf("purge without confirmation: %d %q", code, e)
	}
	// A fresh installation has no legacy data to purge or migrate.
	if code, _, e := runIn(t, "", "webssh", "legacy", "purge", "--yes", "--skip-backup"); code != 1 || !strings.Contains(e, "purge_refused") {
		t.Errorf("purge on a fresh installation: %d %q", code, e)
	}
	if code, _, e := runIn(t, "", "webssh", "migrate", "--dry-run"); code != 1 || !strings.Contains(e, "replace_without_legacy_source") {
		t.Errorf("dry run without legacy data: %d %q", code, e)
	}
	// The registry covers every entity, so --replace gets as far as the
	// missing legacy source.
	if code, _, e := runIn(t, "", "webssh", "migrate", "--replace"); code != 1 || !strings.Contains(e, "replace_without_legacy_source") {
		t.Errorf("replace: %d %q", code, e)
	}
}
