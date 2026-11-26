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
