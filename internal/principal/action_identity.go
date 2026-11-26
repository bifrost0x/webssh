package principal

// Step-up actions of external identity and account administration (M2
// contracts). The names are those the Python release checks and the
// frontend sends (admin.js, webauthn.js), so they stay as they are.
const (
	// ActionUserManage changes an account: lock, unlock, promote, demote,
	// delete. The target is "<user id>:<action>".
	ActionUserManage Action = "user.manage"
	// ActionUserMFAReset removes every second factor of an account.
	ActionUserMFAReset Action = "user.mfa_reset"
	// ActionRecoveryReset replaces the recovery codes of another account.
	ActionRecoveryReset Action = "recovery.reset"

	ActionLDAPLink   Action = "ldap.link"   // target: user id
	ActionLDAPUnlink Action = "ldap.unlink" // target: "<user id>:<identity id>"
	ActionOIDCLink   Action = "oidc.link"   // administrator links a subject; target: user id
	ActionOIDCUnlink Action = "oidc.unlink" // target: "<user id>:<identity id>"
	// ActionOIDCSelfLink links the caller's own account to the provider.
	ActionOIDCSelfLink Action = "oidc.self_link"
	// ActionGitHubConfig changes the GitHub sign-in configuration; target
	// "global".
	ActionGitHubConfig Action = "github.config"
	ActionGitHubLink   Action = "github.link"   // own account
	ActionGitHubUnlink Action = "github.unlink" // own account
)

var identityActions = []Action{
	ActionUserManage, ActionUserMFAReset, ActionRecoveryReset,
	ActionLDAPLink, ActionLDAPUnlink, ActionOIDCLink, ActionOIDCUnlink, ActionOIDCSelfLink,
	ActionGitHubConfig, ActionGitHubLink, ActionGitHubUnlink,
}
