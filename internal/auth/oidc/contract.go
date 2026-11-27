// Package oidc signs in with OpenID Connect (C-IDP-01 to -05): discovery
// and JWKS with time limits, its own JWS check, PKCE, nonce, audience and
// authorized party, subject and domain allowlists, assurance from acr and
// amr, self-linking, administrator linking by subject, and the step-up at
// the provider (prompt=login, max_age=0, OIDC_STEP_UP_ACR_VALUES).
//
// The package satisfies auth.ExternalProvider (name "oidc", callback
// auth.PathOIDCCallback) and auth.IdentityLinks. Its table is
// authoidc_identities, unique (issuer, subject) (E05). OIDC never
// provisions or manages an account: Provision is fault.Forbidden.
package oidc

import (
	"context"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Owner is the schema owner of the package's tables.
const Owner = "authoidc"

// StepUp consumes the grants of oidc.link, oidc.unlink and oidc.self_link
// (internal/auth/stepup).
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// StepUpProofs records a step-up proven at the provider: the callback of
// a flight with auth.PurposeStepUp hands the intent and the provider's
// assurance to internal/auth/stepup, which issues the grant as for every
// other method ("oidc"). The intent must belong to p and still be open.
type StepUpProofs interface {
	ProveExternal(ctx context.Context, p principal.Principal, intent, method string, assurance auth.Assurance) (grant string, err error)
}

// Account is what the OIDC routes read of an account.
type Account struct {
	ID         int64
	Username   string
	Locked     bool
	Generation int64
	// Managed is "", "ldap" or "github" (accounts.Manager): LDAP- and
	// GitHub-managed accounts cannot link an OIDC identity, and an
	// LDAP-managed account cannot sign in with one.
	Managed string
}

// Accounts reads accounts (internal/accounts); an unknown account is
// fault.NotFound. OIDCAccountTx reads inside the caller's transaction, so
// a check and the change it guards commit together.
type Accounts interface {
	OIDCAccount(ctx context.Context, userID int64) (Account, error)
	OIDCAccountTx(ctx context.Context, tx *store.Tx, userID int64) (Account, error)
}

// ProviderStepUp is the part of internal/auth/stepup a provider step-up
// needs: start an administrator intent, check an account intent and
// complete either with the provider's assurance.
type ProviderStepUp interface {
	StepUpProofs
	BeginExternal(ctx context.Context, p principal.Principal, action principal.Action, target, method string) (intent string, err error)
	ExternalIntent(ctx context.Context, p principal.Principal, intent, method string) (required auth.Assurance, err error)
}

// Sessions ends what an unlinked identity gave another account: in the
// transaction that removes the identity, InvalidateTx raises the
// account's generation and ends its sessions (accounts.Service.InvalidateTx);
// Publish runs after the commit (internal/session).
type Sessions interface {
	InvalidateTx(ctx context.Context, tx *store.Tx, userID int64, reason principal.Reason) ([]principal.Revocation, error)
	Publish(revs []principal.Revocation)
}

// Gates reads the administrator switch of the security feature "oidc"
// (internal/operations); a failure counts as off.
type Gates interface {
	Active(ctx context.Context, feature string) (bool, error)
}

// Auditor writes security events (internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}
