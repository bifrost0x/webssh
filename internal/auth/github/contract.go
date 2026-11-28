// Package github signs in with a GitHub App (C-IDP-06 to -09): the
// configuration in the administration with a write-only client secret,
// sign-in by the numeric user id, the organisation allowlist,
// provisioning (in production only with an allowlist), connecting and
// disconnecting the own account.
//
// The package satisfies auth.ExternalProvider (name "github", callback
// auth.PathGitHubCallback) and auth.IdentityLinks. Its tables are
// authgithub_identities (E04), authgithub_config (E06, the client secret
// sealed with keyring.GitHubClientSecret) and authgithub_flights, the
// redirects in progress. The stored redirect_uri is kept byte for byte
// (invariant I-03).
//
// GitHub is no step-up method: its authorization response carries no
// signed time of authentication, so an ambient GitHub session cannot
// prove a fresh sign-in (account_step_up_routes.py). The start route
// refuses, as in the Python release; a GitHub-only account confirms its
// first factor with an operator's bootstrap code instead (auth.Bootstrap).
package github

import (
	"context"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Owner is the schema owner of the package's tables.
const Owner = "authgithub"

// Ring seals the client secret and keys the stored flight values
// (*keyring.Ring).
type Ring interface {
	Seal(p keyring.Purpose, ad keyring.AAD, plain []byte) ([]byte, error)
	Open(p keyring.Purpose, ad keyring.AAD, sealed []byte) ([]byte, error)
	MAC(p keyring.Purpose, msg []byte) []byte
}

// Account is what the package reads of an account.
type Account struct {
	ID         int64
	Username   string
	Locked     bool
	Generation int64
	// Managed is "", "ldap" or "github" (accounts.Manager).
	Managed string
}

// Accounts reads and creates accounts (internal/accounts). ProvisionTx
// creates an account managed by "github" without a local password; a
// taken name is fault.Conflict, a name the account rules refuse
// fault.InvalidValue. HasAccountsTx reports whether any account exists.
// ReleaseTx makes a provisioned account local again
// when its identity is removed; an empty hash keeps it without password.
type Accounts interface {
	AccountTx(ctx context.Context, tx *store.Tx, userID int64) (Account, error)
	ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (userID int64, err error)
	HasAccountsTx(ctx context.Context, tx *store.Tx) (bool, error)
	ReleaseTx(ctx context.Context, tx *store.Tx, userID int64, passwordHash string) error
}

// StepUp consumes the grants of github.config, github.link and
// github.unlink (internal/auth/stepup).
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// Passkeys counts an account's passkeys (internal/auth/webauthn); a
// provisioned account is disconnected from GitHub only once it has one
// (C-IDP-08). Nil counts none.
type Passkeys interface {
	Count(ctx context.Context, tx *store.Tx, userID int64) (int, error)
}

// AdminNames is ADMIN_USERS (accounts.Admins).
type AdminNames interface {
	Reserves(name string) bool
}
