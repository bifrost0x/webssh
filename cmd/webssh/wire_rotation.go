package main

import (
	"context"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/auth/webauthn"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// rotationArea wires the area "rotation" (OP2): secret rotation, maintenance and store repair (internal/backup, internal/admincli).
func rotationArea() extension {
	return extension{name: "rotation"}
}

// Names of the rotation steps whose counts rotate-secret-key prints.
const (
	stepSSHKeys     = "ssh_keys"
	stepCredentials = "credentials"
	stepTOTP        = "totp"
	stepGitHub      = "github_client_secret"
)

// rotationSteps are the capabilities that keep keyring records. Sealed
// records are resealed under the new SECRET_KEY; records kept only as a
// MAC (sessions, step-up grants, pending sign-ins and bootstrap codes)
// cannot be converted and are removed. A capability that adds a sealed
// column and is missing here stops the rotation (backup.ErrRotationLeftover);
// TestRotationCoversEveryTable lists every table of this build.
func rotationSteps() []backup.RotationStep {
	return []backup.RotationStep{
		{Name: stepSSHKeys, Run: vault.ResealKeysTx},
		{Name: stepCredentials, Run: vault.ResealCredentialsTx},
		{Name: stepTOTP, Run: totp.ResealTx},
		{Name: stepGitHub, Run: github.ResealTx},
		{Name: "sessions", Run: removing(session.EndAllTx)},
		{Name: "step_up", Run: removing(stepup.ForgetTx)},
		{Name: "pending_sign_ins", Run: removing(auth.ForgetPendingTx)},
		{Name: "passkey_challenges", Run: removing(webauthn.ForgetChallengesTx)},
	}
}

func removing(f func(context.Context, *store.Tx) (int, error)) func(context.Context, *store.Tx, *keyring.Rotation) (int, error) {
	return func(ctx context.Context, tx *store.Tx, _ *keyring.Rotation) (int, error) { return f(ctx, tx) }
}
