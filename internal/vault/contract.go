// Package vault keeps the user's secrets: SSH keys in M1, saved credentials
// and the import of the legacy automation vault later. Key material is
// sealed with internal/keyring; the package provides client.KeySource.
package vault

import (
	"context"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUp consumes a step-up grant for one action on one target (provided
// by internal/auth/stepup). It fails with fault.StepUpRequired when the
// grant is missing, expired, already used or bound to another user,
// session, action or target; the caller then refuses the operation.
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// Sealer seals and opens private keys at rest (provided by
// *keyring.Ring). Keys are sealed with keyring.SSHKey and bound to their
// row, so a sealed key copied to another row or user does not open.
type Sealer interface {
	Seal(p keyring.Purpose, ad keyring.AAD, plain []byte) ([]byte, error)
	Open(p keyring.Purpose, ad keyring.AAD, sealed []byte) ([]byte, error)
}
