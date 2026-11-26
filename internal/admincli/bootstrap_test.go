package admincli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

type fakeBootstrapAccounts map[string]int64

func (f fakeBootstrapAccounts) ByUsername(_ context.Context, name string) (accounts.Account, error) {
	id, ok := f[name]
	if !ok {
		return accounts.Account{}, fault.New(fault.NotFound, "")
	}
	return accounts.Account{ID: id, Username: name}, nil
}

type fakeIssuer struct{ eligible map[int64]bool }

func (f fakeIssuer) Issue(_ context.Context, id int64, a principal.Action) (string, time.Time, error) {
	if !f.eligible[id] {
		return "", time.Time{}, auth.ErrBootstrapIneligible
	}
	return "code-" + string(a), time.Date(2026, 11, 27, 9, 10, 0, 123456000, time.UTC), nil
}

type auditLog struct{ lines []string }

func (a *auditLog) Security(event string, kv ...any) {
	a.lines = append(a.lines, strings.TrimSpace(event+" "+fmt.Sprintln(kv...)))
}

func runBootstrap(t *testing.T, audit *auditLog, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	opened := false
	code := IssueFactorBootstrap(t.Context(), "webssh", args, IO{Stdout: &out, Stderr: &errOut},
		func(context.Context) (*BootstrapAdmin, func() error, error) {
			opened = true
			return &BootstrapAdmin{Accounts: fakeBootstrapAccounts{"octo": 5, "local": 6}, Bootstrap: fakeIssuer{eligible: map[int64]bool{5: true}},
				Audit: audit}, func() error { return nil }, nil
		})
	if code == ExitUsage && opened {
		t.Fatal("usage error after opening the data")
	}
	return code, out.String(), errOut.String()
}

func TestIssueFactorBootstrap(t *testing.T) {
	t.Parallel()
	usage := "Usage: webssh issue-factor-bootstrap [OPTIONS]\nTry 'webssh issue-factor-bootstrap --help' for help.\n\n"
	cases := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{[]string{"--help"}, ExitOK, strings.ReplaceAll(bootstrapHelp, "%s", "webssh"), ""},
		{nil, ExitUsage, "", usage + "Error: Missing option '--username'.\n"},
		{[]string{"--username", "x"}, ExitUsage, "", usage + "Error: Missing option '--action'. Choose from:\n\tpasskey.enroll,\n\ttotp.enroll\n"},
		{[]string{"--action", "bad"}, ExitUsage, "", usage + "Error: Invalid value for '--action': 'bad' is not one of 'passkey.enroll', 'totp.enroll'.\n"},
		{[]string{"--username", "x", "--action", "Totp.enroll"}, ExitUsage, "", usage + "Error: Invalid value for '--action': 'Totp.enroll' is not one of 'passkey.enroll', 'totp.enroll'.\n"},
		{[]string{"--username", "nobody", "--action", "totp.enroll"}, ExitError, "", "Error: Eligible account not found.\n"},
		{[]string{"--username", "local", "--action", "totp.enroll"}, ExitError, "", "Error: Only a factorless GitHub-provisioned account is eligible.\n"},
		{[]string{"--username=octo", "--action=passkey.enroll"}, ExitOK,
			"Enrollment code: code-passkey.enroll\nExpires at: 2026-11-27T09:10:00.123456Z. This code is single-use and bound to octo and passkey.enroll.\n", ""},
	}
	for _, c := range cases {
		audit := &auditLog{}
		code, out, errOut := runBootstrap(t, audit, c.args...)
		if code != c.code || out != c.stdout || errOut != c.stderr {
			t.Errorf("%q: %d\n%q\n%q", c.args, code, out, errOut)
		}
		if c.code == ExitOK && c.args[0] != "--help" &&
			(len(audit.lines) != 1 || audit.lines[0] != "FACTOR_BOOTSTRAP_ISSUED user octo action passkey.enroll expires_at 2026-11-27T09:10:00.123456+00:00") {
			t.Errorf("audit %q", audit.lines)
		}
	}
}
