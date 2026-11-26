package admincli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// FactorBootstrap issues factor bootstrap codes (auth.Bootstrap).
type FactorBootstrap interface {
	Issue(ctx context.Context, userID int64, action principal.Action) (code string, expires time.Time, err error)
}

// BootstrapAdmin holds what issue-factor-bootstrap needs.
type BootstrapAdmin struct {
	Accounts interface {
		ByUsername(ctx context.Context, name string) (accounts.Account, error)
	}
	Bootstrap FactorBootstrap
	Audit     Auditor
	// Maintenance reports a restore in progress; nil means none.
	Maintenance func() bool
}

// BootstrapOpener prepares the dependencies after the arguments were
// parsed.
type BootstrapOpener func(ctx context.Context) (b *BootstrapAdmin, close func() error, err error)

const bootstrapHelp = `Usage: %s issue-factor-bootstrap [OPTIONS]

  Issue a one-use code for a GitHub-only user's first durable factor.

Options:
  --username NAME                 [required]
  --action [passkey.enroll|totp.enroll]
                                  [required]
  --help                          Show this message and exit.
`

// IssueFactorBootstrap is `webssh issue-factor-bootstrap`: it prints a
// one-time code that confirms the first passkey or authenticator of an
// account GitHub created and that has no factor yet (app/cli.py).
func IssueFactorBootstrap(ctx context.Context, prog string, args []string, o IO, open BootstrapOpener) int {
	c := &command{prog: prog, path: "issue-factor-bootstrap", help: fmt.Sprintf(bootstrapHelp, prog), options: []option{
		{name: "--username", metavar: "NAME", required: true},
		{name: "--action", required: true, choices: []string{"passkey.enroll", "totp.enroll"}},
	}}
	return c.run(o, args, func(p parsed) error {
		b, closeFn, err := open(ctx)
		if err != nil {
			return err
		}
		return errors.Join(b.issue(ctx, p, o), closeFn())
	})
}

func (b *BootstrapAdmin) issue(ctx context.Context, p parsed, o IO) error {
	if b.Maintenance != nil && b.Maintenance() {
		return fail("Factor bootstrap is unavailable during restore maintenance.")
	}
	username, _ := p.value("--username")
	name, _ := p.value("--action")
	action := principal.Action(name)
	acc, err := b.Accounts.ByUsername(ctx, username)
	switch {
	case fault.Is(err, fault.NotFound):
		return fail("Eligible account not found.")
	case err != nil:
		return err
	}
	code, expires, err := b.Bootstrap.Issue(ctx, acc.ID, action)
	if fe, ok := fault.From(err); ok && (fe.Code == fault.Forbidden || fe.Code == fault.InvalidValue) {
		return fail("%s", fe.Message)
	}
	if err != nil {
		return err
	}
	if b.Audit != nil {
		b.Audit.Security("FACTOR_BOOTSTRAP_ISSUED", "user", acc.Username, "action", name, "expires_at", isoUTC(expires, "+00:00"))
	}
	writeLine(o.Stdout, "Enrollment code: "+code)
	writeLine(o.Stdout, "Expires at: "+isoUTC(expires, "Z")+". This code is single-use and bound to "+acc.Username+" and "+name+".")
	return nil
}

// isoUTC is datetime.isoformat() of an aware UTC time with the offset
// written as zone; microseconds appear only when they are not zero.
func isoUTC(t time.Time, zone string) string {
	t = t.UTC()
	layout := "2006-01-02T15:04:05"
	if t.Nanosecond()/1000 != 0 {
		layout += ".000000"
	}
	return t.Format(layout) + zone
}
