package admincli

import (
	"context"
	"errors"
	"fmt"
)

// RotationReport is what rotate-secret-key prints after a rotation.
type RotationReport struct {
	SSHKeys, TOTPSecrets, GitHubSecrets, Credentials int
	// Backup is the verified backup written before the rotation.
	Backup string
}

// SecretRotator rotates SECRET_KEY (provided by the composition root).
type SecretRotator interface {
	// FromEnvironment reports that SECRET_KEY comes from the environment,
	// so the persisted file is not the secret WebSSH uses.
	FromEnvironment() bool
	Rotate(ctx context.Context) (RotationReport, error)
}

// RotatorOpener prepares the rotation after the arguments were parsed.
type RotatorOpener func(ctx context.Context) (r SecretRotator, close func() error, err error)

const rotateHelp = `Usage: %s rotate-secret-key [OPTIONS]

  Rotate the persisted SECRET_KEY and secrets encrypted with it.

Options:
  --confirm-offline
  --help             Show this message and exit.
`

// errSecretFromEnvironment is the refusal of app/cli.py when SECRET_KEY
// is set in the environment.
var errSecretFromEnvironment = fail("SECRET_KEY is set in the environment, so the persisted secret is not the one " +
	"WebSSH uses. Remove SECRET_KEY from the environment or plan the migration described in the backup and secret " +
	"rotation guide; nothing was changed.")

// RotateSecretKey is `webssh rotate-secret-key --confirm-offline`
// (C-BAK-08, app/cli.py): it writes a verified backup, rotates SECRET_KEY
// in DATA_DIR/secret_key and reseals every stored secret under it.
func RotateSecretKey(ctx context.Context, prog string, args []string, o IO, open RotatorOpener) int {
	c := &command{prog: prog, path: "rotate-secret-key", help: fmt.Sprintf(rotateHelp, prog),
		options: []option{{name: "--confirm-offline", flag: true}}}
	return c.run(o, args, func(p parsed) error {
		if err := requireOffline(p); err != nil {
			return err
		}
		r, closeFn, err := open(ctx)
		if err != nil {
			return err
		}
		return errors.Join(rotate(ctx, r, o), closeFn())
	})
}

func rotate(ctx context.Context, r SecretRotator, o IO) error {
	if r.FromEnvironment() {
		return errSecretFromEnvironment
	}
	rep, err := r.Rotate(ctx)
	if err != nil {
		return fail("%s", err.Error())
	}
	writeLine(o.Stdout, fmt.Sprintf("SECRET_KEY rotated for %d stored SSH keys and %d TOTP secrets and %d GitHub client "+
		"secrets and %d named credentials. Verified private recovery snapshot: %s",
		rep.SSHKeys, rep.TOTPSecrets, rep.GitHubSecrets, rep.Credentials, rep.Backup))
	writeLine(o.Stdout, "Restart WebSSH now so every process loads the new persisted secret.")
	return nil
}
