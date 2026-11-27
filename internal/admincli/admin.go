package admincli

import (
	"context"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Accounts is the part of internal/accounts the commands use.
type Accounts interface {
	ByUsername(ctx context.Context, name string) (accounts.Account, error)
	Create(ctx context.Context, req accounts.CreateRequest) (accounts.Account, error)
	Promote(ctx context.Context, id int64) (bool, error)
	PasswordChangedTx(ctx context.Context, tx *store.Tx, id int64, newHash string) (int64, error)
}

// Passwords is the part of internal/auth/local the commands use.
type Passwords interface {
	Hash(ctx context.Context, password string) (string, error)
	StoreTx(ctx context.Context, tx *store.Tx, userID int64, hash string) error
}

// Sessions is the part of internal/session the commands use.
// RevokeAccountTx journals an account-wide revocation even when the
// account has no browser session left, so the running server ends its
// terminals and persistent tmux sessions as well.
type Sessions interface {
	RevokeAccountTx(ctx context.Context, tx *store.Tx, userID int64, reason principal.Reason) ([]principal.Revocation, error)
}

// Auditor writes security audit events (internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}

// Admin holds what create-admin and reset-password need. The composition
// root opens the Go database and wires the services.
type Admin struct {
	DB        *store.DB
	Accounts  Accounts
	Passwords Passwords
	Sessions  Sessions
	Audit     Auditor
}

// Opener prepares the dependencies of a command. It runs only after the
// arguments were parsed, so that usage errors and --help never touch the
// data directory, as with Click. close releases what it opened.
type Opener func(ctx context.Context) (a *Admin, close func() error, err error)

func passwordCommand(prog, name, help string) *command {
	return &command{prog: prog, path: name, help: help, options: []option{
		{name: "--username", metavar: "NAME", required: true},
		{name: "--password-file", metavar: "PATH"},
	}}
}

const createAdminHelp = `Usage: %s create-admin [OPTIONS]

  Create a new administrator or promote an existing account.

Options:
  --username NAME       [required]
  --password-file PATH
  --help                Show this message and exit.
`

const resetHelp = `Usage: %s reset-password [OPTIONS]

  Set a new password for a local account and end its sign-ins.

  For a forgotten password, including the only administrator's. Needs shell
  access to the host, which already grants control over the data.

Options:
  --username NAME       [required]
  --password-file PATH
  --help                Show this message and exit.
`

// CreateAdmin is `webssh create-admin`: it promotes an existing local
// account or creates a new administrator, with the options, messages and
// exit codes of app/cli.py. prog is the program name for usage lines.
func CreateAdmin(ctx context.Context, prog string, args []string, o IO, open Opener) int {
	c := passwordCommand(prog, "create-admin", fmt.Sprintf(createAdminHelp, prog))
	return c.run(o, args, func(p parsed) error {
		a, closeFn, err := open(ctx)
		if err != nil {
			return err
		}
		return errors.Join(a.createAdmin(ctx, p, o), closeFn())
	})
}

func (a *Admin) createAdmin(ctx context.Context, p parsed, o IO) error {
	username, _ := p.value("--username")
	passwordFile, hasFile := p.value("--password-file")
	acc, err := a.Accounts.ByUsername(ctx, username)
	switch {
	case err == nil:
		return a.promote(ctx, acc, hasFile, o)
	case !fault.Is(err, fault.NotFound):
		return err
	}
	password, err := readPassword(o, hasFile, passwordFile, "Password")
	if err != nil {
		return err
	}
	acc, err = a.Accounts.Create(ctx, accounts.CreateRequest{Username: username, Password: password, ByAdmin: true, Admin: true})
	if fe, ok := fault.From(err); ok && fe.Code == fault.InvalidValue {
		return fail("%s", fe.Message)
	}
	if err != nil {
		return err
	}
	a.audit("ADMIN_BOOTSTRAP_SUCCESS", "user", acc.Username, "action", "created")
	writeLine(o.Stdout, "Administrator created: "+acc.Username)
	return nil
}

func (a *Admin) promote(ctx context.Context, acc accounts.Account, hasFile bool, o IO) error {
	if msg := managedPromoteMessage(acc.Managed); msg != "" {
		return fail("%s", msg)
	}
	if hasFile {
		return fail("--password-file cannot be used when promoting an existing user.")
	}
	changed, err := a.Accounts.Promote(ctx, acc.ID)
	switch {
	case errors.Is(err, accounts.ErrPromoteLDAP):
		return fail("%s", managedPromoteMessage(accounts.ManagedLDAP))
	case errors.Is(err, accounts.ErrPromoteGitHub):
		return fail("%s", managedPromoteMessage(accounts.ManagedGitHub))
	case err != nil:
		return err
	}
	action := "already_admin"
	if changed {
		action = "promoted"
	}
	a.audit("ADMIN_BOOTSTRAP_SUCCESS", "user", acc.Username, "action", action)
	writeLine(o.Stdout, "Administrator ready: "+acc.Username)
	return nil
}

func managedPromoteMessage(m accounts.Manager) string {
	switch m {
	case accounts.ManagedLDAP:
		return "LDAP-managed accounts cannot be administrators."
	case accounts.ManagedGitHub:
		return "GitHub-managed accounts cannot be administrators."
	}
	return ""
}

// ResetPassword is `webssh reset-password`: it sets a new password for a
// local account, raises its authentication generation and ends every
// session of it in one transaction.
func ResetPassword(ctx context.Context, prog string, args []string, o IO, open Opener) int {
	c := passwordCommand(prog, "reset-password", fmt.Sprintf(resetHelp, prog))
	return c.run(o, args, func(p parsed) error {
		a, closeFn, err := open(ctx)
		if err != nil {
			return err
		}
		return errors.Join(a.resetPassword(ctx, p, o), closeFn())
	})
}

func (a *Admin) resetPassword(ctx context.Context, p parsed, o IO) error {
	username, _ := p.value("--username")
	passwordFile, hasFile := p.value("--password-file")
	acc, err := a.Accounts.ByUsername(ctx, username)
	switch {
	case fault.Is(err, fault.NotFound):
		return fail("Account not found.")
	case err != nil:
		return err
	case acc.Managed == accounts.ManagedLDAP:
		return fail("The password of an LDAP-managed account is set in the directory.")
	case acc.Managed == accounts.ManagedGitHub:
		return fail("GitHub-managed accounts sign in through GitHub and have no local password.")
	}
	password, err := readPassword(o, hasFile, passwordFile, "New password")
	if err != nil {
		return err
	}
	if msg := local.ValidateNew(password); msg != "" {
		return fail("%s", msg)
	}
	hash, err := a.Passwords.Hash(ctx, password)
	if err != nil {
		return err
	}
	err = a.DB.Write(ctx, func(tx *store.Tx) error {
		if err := a.Passwords.StoreTx(ctx, tx, acc.ID, hash); err != nil {
			return err
		}
		if _, err := a.Accounts.PasswordChangedTx(ctx, tx, acc.ID, hash); err != nil {
			return err
		}
		_, err := a.Sessions.RevokeAccountTx(ctx, tx, acc.ID, principal.ReasonPasswordChanged)
		return err
	})
	if err != nil {
		return fmt.Errorf("the password was not changed: %w", err)
	}
	a.audit("PASSWORD_RESET_CLI", "user", acc.Username)
	// The running server follows the session revocation journal and ends
	// the browser connections, terminals and SSH sessions of the account
	// within a few seconds, as the Python release did.
	writeLine(o.Stdout, "Password reset for "+acc.Username+". Its sign-ins are invalid. If WebSSH is running, "+
		"its open connections, SSH sessions and persistent tmux sessions end within a few seconds.")
	if acc.IsLocked {
		writeLine(o.Stdout, "The account is still locked; an administrator can unlock it.")
	}
	return nil
}

func readPassword(o IO, hasFile bool, path, prompt string) (string, error) {
	if hasFile {
		return readPasswordFile(path, local.MaxPasswordBytes)
	}
	return newPrompter(o).clickPassword(prompt)
}

func (a *Admin) audit(event string, kv ...any) {
	if a.Audit != nil {
		a.Audit.Security(event, kv...)
	}
}

// run parses args, prints --help or runs fn, and reports the outcome.
func (c *command) run(o IO, args []string, fn func(parsed) error) int {
	p, err := c.parse(args)
	if err == nil && p.help {
		_, _ = fmt.Fprint(o.Stdout, c.help)
		return ExitOK
	}
	if err == nil {
		err = fn(p)
	}
	return c.report(o, err)
}
