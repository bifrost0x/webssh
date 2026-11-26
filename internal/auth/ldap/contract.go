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

// Accounts creates and converts directory accounts (internal/accounts).
// ProvisionTx creates an account managed by "ldap" with no local password;
// a taken name is fault.Conflict. ReleaseTx turns a managed account back
// into a local one with the given password hash when the administrator
// unlinks the identity (ldap_routes.py: unlink requires a new password).
type Accounts interface {
	ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (userID int64, err error)
	ReleaseTx(ctx context.Context, tx *store.Tx, userID int64, passwordHash string) error
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
