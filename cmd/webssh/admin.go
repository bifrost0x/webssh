package main

import (
	"context"
	"errors"
	"io"

	"github.com/bifrost0x/webssh/internal/admincli"
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
// their arguments were parsed. Warnings of the start-up state (for
// example S5) go to stderr.
func openAdmin(stderr io.Writer) admincli.Opener {
	return func(ctx context.Context) (*admincli.Admin, func() error, error) {
		cfg, err := loadConfig()
		if err != nil {
			return nil, nil, err
		}
		g, err := openGoData(ctx, cfg)
		if se, ok := errors.AsType[*legacy.StopError](err); ok {
			return nil, nil, errors.New(se.Message)
		}
		if err != nil {
			return nil, nil, err
		}
		if g.startup != nil {
			for _, w := range g.startup.Warnings {
				write(stderr, "Warning: "+w.Message+"\n")
			}
		}
		a := &admincli.Admin{DB: g.db, Accounts: g.accounts, Passwords: g.local, Sessions: g.sessions, Audit: g.audit}
		return a, g.Close, nil
	}
}
