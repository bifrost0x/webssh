package principal

// Step-up actions of operation and administration (M2 contracts), named
// as in the Python release.
const (
	ActionSettingsUpdate Action = "settings.update" // target "global"
	ActionAuditRetention Action = "audit.retention" // target "global"

	ActionBackupCreate         Action = "backup.create"          // target "new"
	ActionBackupCancel         Action = "backup.cancel"          // target: operation id
	ActionBackupDownload       Action = "backup.download"        // target: operation id
	ActionBackupUpload         Action = "backup.upload"          // target "upload"
	ActionBackupRestorePrepare Action = "backup.restore_prepare" // target: operation id
	ActionBackupRestore        Action = "backup.restore"         // target: operation id

	// The targets of the operations actions are the opaque references of
	// the operations view, never a raw session or socket id.
	ActionOperationsSessionDisconnect    Action = "operations.session.disconnect"
	ActionOperationsConnectionDisconnect Action = "operations.connection.disconnect"
	ActionOperationsTransferCancel       Action = "operations.transfer.cancel"

	ActionHostKeyGlobalAdd    Action = "host_key.global_add"    // target "global"
	ActionHostKeyGlobalDelete Action = "host_key.global_delete" // target: entry id

	// ActionServerOperation runs a server operation the caller confirmed;
	// the target is the operation intent.
	ActionServerOperation Action = "server.operation"
)

var operationActions = []Action{
	ActionSettingsUpdate, ActionAuditRetention,
	ActionBackupCreate, ActionBackupCancel, ActionBackupDownload, ActionBackupUpload,
	ActionBackupRestorePrepare, ActionBackupRestore,
	ActionOperationsSessionDisconnect, ActionOperationsConnectionDisconnect, ActionOperationsTransferCancel,
	ActionHostKeyGlobalAdd, ActionHostKeyGlobalDelete,
	ActionServerOperation,
}
