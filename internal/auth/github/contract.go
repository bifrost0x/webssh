// Package github signs in with a GitHub OAuth app (C-IDP-06 to -09): the
// configuration in the administration with a write-only client secret,
// sign-in by the numeric user id, the organisation allowlist,
// provisioning (in production only with an allowlist), connecting and
// disconnecting the own account, and the GitHub step-up proof.
//
// The package satisfies auth.ExternalProvider (name "github", callback
// auth.PathGitHubCallback) and auth.IdentityLinks. Its tables are
// authgithub_identities (E04) and authgithub_config (E06, the client
// secret sealed with keyring.GitHubClientSecret). The stored redirect_uri
// is kept byte for byte (invariant I-03).
package github

import (
	"context"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Owner is the schema owner of the package's tables.
const Owner = "authgithub"

// Accounts creates GitHub-managed accounts (internal/accounts); see
// ldap.Accounts for the rules of ProvisionTx.
type Accounts interface {
	ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (userID int64, err error)
}

// StepUp consumes the grants of github.config, github.link and
// github.unlink (internal/auth/stepup). A provisioned account is
// disconnected only once it has a passkey (C-IDP-08).
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// StepUpProofs records a step-up proven at GitHub ("github"); see
// oidc.StepUpProofs.
type StepUpProofs interface {
	ProveExternal(ctx context.Context, p principal.Principal, intent, method string, assurance auth.Assurance) (grant string, err error)
}
