package main

import (
	"context"
	"errors"
	"io"

	"github.com/bifrost0x/webssh/internal/admincli"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/auth/webauthn"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
)

// adminRun runs an administrator command; prog is the program name in
// its usage lines ("webssh", or "flask" under the deprecated form).
type adminRun func(ctx context.Context, prog string, args []string, s streams) int

func runCreateAdmin(ctx context.Context, args []string, s streams) int {
	return createAdmin(ctx, "webssh", args, s)
}

func runResetPassword(ctx context.Context, args []string, s streams) int {
	return resetPassword(ctx, "webssh", args, s)
}

func createAdmin(ctx context.Context, prog string, args []string, s streams) int {
	return admincli.CreateAdmin(ctx, prog, args, cliIO(s), openAdmin(s.stderr))
}

func resetPassword(ctx context.Context, prog string, args []string, s streams) int {
	return admincli.ResetPassword(ctx, prog, args, cliIO(s), openAdmin(s.stderr))
}

func runIssueFactorBootstrap(ctx context.Context, args []string, s streams) int {
	return issueFactorBootstrap(ctx, "webssh", args, s)
}

func issueFactorBootstrap(ctx context.Context, prog string, args []string, s streams) int {
	return admincli.IssueFactorBootstrap(ctx, prog, args, cliIO(s), openBootstrap(s.stderr))
}

// openBootstrap opens the Go data for issue-factor-bootstrap.
func openBootstrap(stderr io.Writer) admincli.BootstrapOpener {
	return func(ctx context.Context) (*admincli.BootstrapAdmin, func() error, error) {
		g, err := openCommandData(ctx, stderr)
		if err != nil {
			return nil, nil, err
		}
		boot := newBootstrap(g.db, g.ring, g.accounts, &totp.Service{DB: g.db}, &webauthn.Service{DB: g.db})
		return &admincli.BootstrapAdmin{Accounts: g.accounts, Bootstrap: boot, Audit: g.audit}, g.Close, nil
	}
}

func runLDAPSecret(_ context.Context, args []string, s streams) int {
	return runLDAPSecretAs("webssh ldap-secret", args, s)
}

func runLDAPSecretAs(prog string, args []string, s streams) int {
	return admincli.LDAPSecret(prog, args, cliIO(s))
}

// terminalOpener is replaced in tests, which have no controlling
// terminal to offer.
var terminalOpener = admincli.OpenTerminal

func cliIO(s streams) admincli.IO {
	return admincli.IO{Stdin: s.stdin, Stdout: s.stdout, Stderr: s.stderr, Terminal: terminalOpener}
}

// openAdmin opens the Go data for create-admin and reset-password after
// their arguments were parsed.
func openAdmin(stderr io.Writer) admincli.Opener {
	return func(ctx context.Context) (*admincli.Admin, func() error, error) {
		g, err := openCommandData(ctx, stderr)
		if err != nil {
			return nil, nil, err
		}
		a := &admincli.Admin{DB: g.db, Accounts: g.accounts, Passwords: g.local, Sessions: g.sessions, Audit: g.audit}
		return a, g.Close, nil
	}
}

// openCommandData opens the Go data for an administrator command.
// Warnings of the start-up state (for example S5) go to stderr.
func openCommandData(ctx context.Context, stderr io.Writer) (*goData, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	g, err := openGoData(ctx, cfg)
	if se, ok := errors.AsType[*legacy.StopError](err); ok {
		return nil, errors.New(se.Message)
	}
	if err != nil {
		return nil, err
	}
	if g.startup != nil {
		for _, w := range g.startup.Warnings {
			write(stderr, "Warning: "+w.Message+"\n")
		}
	}
	return g, nil
}
