package auth

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// ProviderName names an external identity provider. The values of LDAP
// and GitHub are also the accounts.Manager values of the accounts they
// provision; OIDC never manages an account (models.py: only LDAP and
// GitHub identities make an account managed).
type ProviderName string

// External providers (docs/architecture/m2-contracts.md).
const (
	ProviderLDAP   ProviderName = "ldap"
	ProviderOIDC   ProviderName = "oidc"
	ProviderGitHub ProviderName = "github"
)

// Paths of the external sign-in routes, relative to the application
// root. The callback paths are registered at the identity providers and
// stored in the GitHub configuration (redirect_uri), so they never change
// (invariant I-03); the route catalog of internal/httpapi is tested
// against them.
const (
	PathLDAPLogin      = "/login/ldap"
	PathOIDCLogin      = "/oidc/login"
	PathOIDCCallback   = "/oidc/callback"
	PathGitHubLogin    = "/auth/github/login"
	PathGitHubCallback = "/auth/github/callback"
)

// Purpose says why a redirect provider is asked; the values are those of
// the Python login state (oidc_routes.py, github_auth_routes.py).
type Purpose string

// Purposes of a redirect.
const (
	// PurposeSignIn signs in; the callback starts the pending sign-in of
	// internal/auth, so second factors still apply.
	PurposeSignIn Purpose = "login"
	// PurposeLink binds the identity to the signed-in account (own account
	// only). The provider is asked to authenticate again.
	PurposeLink Purpose = "link"
	// PurposeStepUp proves the user again for one step-up intent; the
	// provider is asked to authenticate again (prompt=login, max_age=0
	// for OIDC).
	PurposeStepUp Purpose = "step_up"
)

// Identity is what an external provider vouches for. Subject is the
// stable key of the identity table: the OIDC sub, the numeric GitHub user
// id, the canonical LDAP unique attribute. Login names can change and are
// never used to find an account.
type Identity struct {
	Provider ProviderName
	// Issuer is the OIDC issuer, the LDAP provider id (LDAP_PROVIDER_ID)
	// or "" for GitHub.
	Issuer  string
	Subject string
	// Username is the name the provider shows (directory username, GitHub
	// login, preferred_username); it proposes the name of an account that
	// is provisioned and is shown in the administration.
	Username      string
	DisplayName   string
	Email         string
	EmailVerified bool
	// DistinguishedName is the entry of an LDAP identity.
	DistinguishedName string
	// Assurance is what the provider's authentication is worth here: BASIC,
	// or more for OIDC when acr or amr meet OIDC_MFA_* or
	// OIDC_PHISHING_RESISTANT_* (C-IDP-04). Methods are the amr values.
	Assurance Assurance
	Methods   []string
}

// ExternalProvider is a redirect sign-in provider (OIDC, GitHub). The
// flow of internal/auth stores the Flight from Begin, bound to the
// browser, and hands it to Complete with the callback; providers keep no
// per-request state of their own.
type ExternalProvider interface {
	Name() ProviderName
	// Begin returns the authorization URL for the flight; f carries the
	// state, nonce and PKCE verifier the provider put into it.
	Begin(ctx context.Context, f Flight) (redirectURL string, err error)
	// Complete checks the callback against f (Flight.Accept first, then
	// the provider's own checks: code exchange with the verifier, ID
	// token, nonce, audience, allowlists) and returns the identity.
	// Every refusal is fault.AuthFailed without provider text, except an
	// unreachable provider, which is fault.Unavailable.
	Complete(ctx context.Context, f Flight, cb Callback) (Identity, error)
}

// LinkedIdentity is one row of a provider's identity table as the
// administration and the account page show it.
type LinkedIdentity struct {
	ID       int64
	UserID   int64
	Provider ProviderName
	Issuer   string
	Subject  string
	Username string
	// Provisioned is set when the provider created the account
	// (provisioned_by_github; LDAP accounts it created).
	Provisioned    bool
	CreatedAt      time.Time
	LastVerifiedAt time.Time
}

// IdentityLinks maps identities of one provider to accounts. Each
// provider package owns its identity table (authldap_identities,
// authoidc_identities, authgithub_identities) and implements this; the
// flow and the administration consume it.
//
// The rules (migration specification E03 to E05, C-IDP-*):
//   - (Issuer, Subject) is unique, and an account has at most one identity
//     per LDAP provider and one GitHub identity; a second link is
//     fault.Conflict, never a silent move to another account.
//   - Account returns fault.NotFound for an identity without a link. The
//     caller then provisions (Provision) or refuses; it never matches an
//     account by name or e-mail.
//   - Provision creates an account only where the provider's policy allows
//     it (LDAP_AUTO_PROVISION, GitHub auto_provision with the organisation
//     allowlist, which production requires); otherwise fault.Forbidden. A
//     name that is taken is never reused: the provider derives a free one
//     or refuses with fault.Conflict.
//   - LinkTx, Unlink and Provision run in the caller's step-up: the
//     consumer has consumed the grant before it calls them.
type IdentityLinks interface {
	Account(ctx context.Context, id Identity) (userID int64, err error)
	Provision(ctx context.Context, id Identity) (userID int64, err error)
	LinkTx(ctx context.Context, tx *store.Tx, userID int64, id Identity) (LinkedIdentity, error)
	Unlink(ctx context.Context, userID, identityID int64) error
	List(ctx context.Context, userID int64) ([]LinkedIdentity, error)
}

// Revalidator re-checks the external standing of a signed-in account
// (LDAP: the entry still exists, matches the filter and has the same
// unique attribute; LDAP_SESSION_REVALIDATION_SECONDS). A refusal revokes
// the account's sessions through internal/session before it returns; a
// directory that cannot be reached counts as a refusal (fail closed, as
// in ldap_session.py). It runs as a background job (internal/jobs) and on
// demand before a request when the last check is older than the interval.
type Revalidator interface {
	Revalidate(ctx context.Context, userID int64) error
}
