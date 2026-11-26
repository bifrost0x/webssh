package stepup

import "github.com/bifrost0x/webssh/internal/principal"

// Every action of the catalog belongs to exactly one audience; the tests
// fail for an action that has none, so a new action cannot be granted to
// a principal it was not meant for.

// adminActions need an administrator.
var adminActions = []principal.Action{
	principal.ActionSecurityFeatureUpdate, principal.ActionUserCreate,

	principal.ActionUserManage, principal.ActionUserMFAReset, principal.ActionRecoveryReset,
	principal.ActionLDAPLink, principal.ActionLDAPUnlink, principal.ActionOIDCLink, principal.ActionOIDCUnlink,
	principal.ActionGitHubConfig,
	principal.ActionSettingsUpdate, principal.ActionAuditRetention,
	principal.ActionBackupCreate, principal.ActionBackupCancel, principal.ActionBackupDownload,
	principal.ActionBackupUpload, principal.ActionBackupRestorePrepare, principal.ActionBackupRestore,
	principal.ActionOperationsSessionDisconnect, principal.ActionOperationsConnectionDisconnect,
	principal.ActionOperationsTransferCancel,
	principal.ActionHostKeyGlobalAdd, principal.ActionHostKeyGlobalDelete,
}

// selfActions target the principal's own account; the target defaults to
// the user id and must equal it. key.upload is one of them: the page
// sends no target and the vault binds the grant to the user id.
var selfActions = []principal.Action{
	principal.ActionTOTPEnroll, principal.ActionPasskeyEnroll, principal.ActionMFAEnable,
	principal.ActionMFADisable, principal.ActionRecoveryRotate, principal.ActionKeyUpload,

	principal.ActionOIDCSelfLink, principal.ActionGitHubLink, principal.ActionGitHubUnlink,
}

// accountActions are open to every signed-in principal and bound to a
// target the consumer checks (ownership through Targets or the consumer's
// own lookup before Consume).
var accountActions = []principal.Action{
	principal.ActionKeyReplace, principal.ActionKeyDelete, principal.ActionHostKeyDelete,
	principal.ActionTOTPDelete, principal.ActionPasskeyDelete,

	principal.ActionServerOperation,

	// The target is the intent token of the saved-password change; the vault
	// binds the intent to the user and the session.
	principal.ActionCredentialsVault,
}
