// Package ldap signs in with LDAP and Active Directory (C-IDP-10 to -14):
// search with the service account, bind as the user, map the unique
// attribute to an account, provision when LDAP_AUTO_PROVISION allows it,
// re-check signed-in accounts against the directory and offer the LDAP
// step-up proof. The wire protocol is internal/ldapproto.
//
// The package satisfies auth.Provider (name "ldap"), auth.IdentityLinks
// and auth.Revalidator. Its tables are authldap_identities (E03) and
// authldap_revalidation (E37: accounts that must pass a directory check
// before any access). The interfaces below are what it consumes; the
// composition root (cmd/webssh/wire_ldap.go) checks the providers at
// compile time.
package ldap

import (
	"context"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Owner is the schema owner of the package's tables.
const Owner = "authldap"

// Account is what the package reads of an account.
type Account struct {
	ID         int64
	Username   string
	IsAdmin    bool
	IsLocked   bool
	Generation int64
	// Managed is the accounts.Manager value: "", "ldap" or "github".
	Managed string
}

// Accounts creates, reads and converts directory accounts
// (internal/accounts).
//
// ProvisionTx creates a non-admin account managed by "ldap" with no
// usable local password; a name equal to an existing one after case
// folding is fault.Conflict. ReleaseTx turns a managed account back into a
// local one with the given password hash when the administrator unlinks
// the identity (ldap_routes.py: unlink requires a new password); AdoptTx
// makes a local account managed by "ldap" and replaces its password with
// an unusable one (ldap_routes.py: link destroys the dormant password).
// Both raise the auth generation, which ends every credential issued
// before. RaiseGenerationTx does only that. BreakGlassAdminTx reports
// whether an unlocked administrator exists that is not managed by LDAP;
// auto-provisioning needs one.
type Accounts interface {
	GetTx(ctx context.Context, tx *store.Tx, userID int64) (Account, error)
	ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (userID int64, err error)
	ReleaseTx(ctx context.Context, tx *store.Tx, userID int64, passwordHash string) error
	AdoptTx(ctx context.Context, tx *store.Tx, userID int64, manager string) error
	RaiseGenerationTx(ctx context.Context, tx *store.Tx, userID int64) error
	BreakGlassAdminTx(ctx context.Context, tx *store.Tx) (bool, error)
}

// Sessions ends the sessions of an account whose directory check failed
// (internal/session).
type Sessions interface {
	RevokeUser(ctx context.Context, userID int64, reason principal.Reason, except string) (int, error)
}

// StepUp consumes the grants of ldap.link and ldap.unlink
// (internal/auth/stepup).
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// Passwords checks and hashes the new local password of an unlinked
// account (internal/auth/local).
type Passwords interface {
	ValidateNew(password string) string
	Hash(ctx context.Context, password string) (string, error)
}

// Identities removes the OIDC identities of an account that becomes
// LDAP-managed, as linking did in the Python release (internal/auth/oidc;
// nil until OIDC is built, then nothing is removed).
type Identities interface {
	RemoveAllTx(ctx context.Context, tx *store.Tx, userID int64) error
}

// Gates says whether the security feature "ldap" is active
// (operations.Gates); an inactive feature answers 404 on its routes.
type Gates interface {
	Active(ctx context.Context, feature string) (bool, error)
}

// Auditor writes the security audit log (internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}

// Directory is the LDAP server as the package uses it; *Client provides
// it.
type Directory interface {
	Lookup(ctx context.Context, username string) (Entry, error)
	VerifyPassword(ctx context.Context, dn, password string) (bool, error)
	Probe(ctx context.Context) error
	Ready() error
	Transport() string
}
