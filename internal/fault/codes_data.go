package fault

import "fmt"

// Codes of the file workspace and the transfers. The spelling is that of
// the Python release (app/file_mutations.py, app/file_backend.py,
// app/transfer_errors.py, app/smb_protocol.py): the file pages and
// static/js match on the upper-case codes, so they stay as they are next to
// the lower-case codes of the other capabilities.
const (
	FilePermissionDenied      Code = "PERMISSION_DENIED"
	FileConflict              Code = "CONFLICT"
	FileNotFound              Code = "NOT_FOUND"
	FileTimeout               Code = "TIMEOUT"
	FileCancelled             Code = "CANCELLED"
	SourceUnavailable         Code = "SOURCE_UNAVAILABLE"
	SourceChanged             Code = "SOURCE_CHANGED"
	LimitExceeded             Code = "LIMIT_EXCEEDED"
	AtomicReplaceUnavailable  Code = "ATOMIC_REPLACE_UNAVAILABLE"
	TransferUnavailable       Code = "TRANSFER_UNAVAILABLE"
	UnsupportedOperation      Code = "UNSUPPORTED_OPERATION"
	MetadataChanged           Code = "METADATA_CHANGED"
	OperationFailed           Code = "OPERATION_FAILED"
	OutcomeUnknown            Code = "OUTCOME_UNKNOWN"
	ModeMismatch              Code = "MODE_MISMATCH"
	FileExpired               Code = "EXPIRED"
	EditConflict              Code = "EDIT_CONFLICT" // the stored revision is stale
	EditEncodingUnsupported   Code = "EDIT_ENCODING_UNSUPPORTED"
	EditMetadataUnsupported   Code = "EDIT_METADATA_UNSUPPORTED"
	SaveOutcomeUnknown        Code = "SAVE_OUTCOME_UNKNOWN"
	FileTooLarge              Code = "FILE_TOO_LARGE" // new: Python sent only a text
	FileBinary                Code = "FILE_BINARY"    // new: Python sent only a text
	SMBRecoverableReplaceNeed Code = "SMB_RECOVERABLE_REPLACE_REQUIRED"
	SMBRecoverableReplaceFail Code = "SMB_RECOVERABLE_REPLACE_FAILED"
	SMBRecoveryRequired       Code = "SMB_RECOVERY_REQUIRED"
	ShareUnavailable          Code = "SHARE_UNAVAILABLE"
	SMBAuthenticationRequired Code = "AUTHENTICATION_REQUIRED"
	SMBOperationUnavailable   Code = "OPERATION_UNAVAILABLE"
	SMBIdentityUnavailable    Code = "IDENTITY_UNAVAILABLE"
	SMBReparsePointRejected   Code = "REPARSE_POINT_REJECTED"
	SMBMutationGuardRequired  Code = "MUTATION_GUARD_REQUIRED"
	SMBConnectCancelled       Code = "CONNECT_CANCELLED"
	SMBConnectionFailed       Code = "CONNECTION_FAILED"
	SMBQuotaExceeded          Code = "QUOTA_EXCEEDED"
	SMBRuntimeShuttingDown    Code = "RUNTIME_SHUTTING_DOWN"
	SMBTargetNotAllowed       Code = "TARGET_NOT_ALLOWED"
	SMBEncryptionRequired     Code = "ENCRYPTION_REQUIRED" // new (K1): the server refused encryption
	SMBDialectRequired        Code = "DIALECT_REQUIRED"    // new (K1): no SMB 3.1.1
)

// HTTP status codes used only by these codes.
const (
	statusLocked               = 423
	statusUnsupportedMediaType = 415
)

// Codes of the saved passwords (app/credential_routes.py,
// app/credential_service.py) and of schedules (app/automation_cron.py);
// the spelling stays.
const (
	HTTPSRequired                   Code = "https_required"
	CredentialsDisabled             Code = "credentials_disabled"
	InvalidIntent                   Code = "invalid_intent"
	PreviewChanged                  Code = "preview_changed"
	CredentialInUse                 Code = "credential_in_use" // #nosec G101 -- an error code, not a credential
	VaultLocked                     Code = "vault_locked"
	InvalidTargets                  Code = "invalid_targets"
	CredentialTargetChanged         Code = "credential_target_changed" // #nosec G101 -- an error code, not a credential
	CredentialMissing               Code = "credential_missing"        // #nosec G101 -- an error code, not a credential
	CredentialUnreadable            Code = "credential_unreadable"     // #nosec G101 -- an error code, not a credential
	CredentialUnavailable           Code = "credential_unavailable"    // #nosec G101 -- an error code, not a credential
	StorageLimit                    Code = "storage_limit"
	ReplacementConfirmationRequired Code = "replacement_confirmation_required"
	ConfirmationRequired            Code = "confirmation_required"
	VaultMissing                    Code = "vault_missing"
	VaultUnreadable                 Code = "vault_unreadable"
	VaultUnlockFailed               Code = "vault_unlock_failed"
	InvalidPassphrase               Code = "invalid_passphrase"
	InvalidSchedule                 Code = "invalid_schedule"
)

// dataCatalog holds the codes of the file, transfer, credential and
// schedule capabilities (M2 contracts). It is kept apart from catalog so
// that the parallel packages add their codes without touching the M1 list.
var dataCatalog = map[Code]entry{
	FilePermissionDenied:     {statusForbidden, "Permission denied for this file operation."},
	FileConflict:             {statusConflict, "A file or folder already exists at the destination."},
	FileNotFound:             {statusNotFound, "The requested file or folder was not found."},
	FileTimeout:              {statusGatewayTimeout, "The file operation timed out."},
	FileCancelled:            {statusConflict, "The operation was cancelled."},
	SourceUnavailable:        {statusNotFound, "The file source is no longer available. Reconnect and try again."},
	SourceChanged:            {statusConflict, "The source changed during the operation. Try again."},
	LimitExceeded:            {statusContentTooLarge, "The transfer exceeds the configured limit."},
	AtomicReplaceUnavailable: {statusConflict, "Safe overwrite is unavailable for this destination."},
	TransferUnavailable:      {statusInternalServerError, "The transfer could not be completed."},
	UnsupportedOperation:     {statusBadRequest, "This file source does not support the operation."},
	MetadataChanged:          {statusConflict, "The file changed. Reload and try again."},
	OperationFailed:          {statusBadGateway, "The file operation failed."},
	OutcomeUnknown:           {statusBadGateway, "The outcome of the operation is unknown. Reload to check."},
	ModeMismatch:             {statusConflict, "The permissions were not applied as requested."},
	FileExpired:              {statusConflict, "The preview has expired. Start again."},
	EditConflict:             {statusConflict, "The file changed since it was opened."},
	EditEncodingUnsupported:  {statusBadRequest, "The text cannot be saved in the file's encoding."},
	EditMetadataUnsupported:  {statusConflict, "The file's owner or special permissions prevent a safe save."},
	SaveOutcomeUnknown:       {statusBadGateway, "The outcome of the save is unknown. Reload to check."},
	FileTooLarge:             {statusContentTooLarge, "The file is too large."},
	FileBinary:               {statusUnsupportedMediaType, "Binary files cannot be shown as text."},

	SMBRecoverableReplaceNeed: {statusConflict, "Saving this file needs a recoverable replace. Confirm to continue."},
	SMBRecoverableReplaceFail: {statusBadGateway, "The file could not be replaced; the original was restored."},
	SMBRecoveryRequired:       {statusBadGateway, "The save outcome is uncertain. Check the recovery files."},
	ShareUnavailable:          {statusNotFound, "The SMB share is unavailable."},
	SMBAuthenticationRequired: {statusBadGateway, "The SMB server requires valid credentials."},
	SMBOperationUnavailable:   {statusBadGateway, "The SMB server does not support this operation."},
	SMBIdentityUnavailable:    {statusBadGateway, "SMB object identity is unavailable."},
	SMBReparsePointRejected:   {statusForbidden, "Reparse points are not supported."},
	SMBMutationGuardRequired:  {statusConflict, "SMB mutation safety check failed."},
	SMBConnectCancelled:       {statusBadRequest, "The SMB connection was cancelled."},
	SMBConnectionFailed:       {statusBadGateway, "The SMB connection failed."},
	SMBQuotaExceeded:          {statusConflict, "Too many SMB connections are open."},
	SMBRuntimeShuttingDown:    {statusServiceUnavailable, "The server is shutting down."},
	SMBTargetNotAllowed:       {statusForbidden, "The SMB target is not allowed."},
	SMBEncryptionRequired:     {statusBadGateway, "The SMB server does not offer the required encryption."},
	SMBDialectRequired:        {statusBadGateway, "The SMB server does not support SMB 3.1.1."},

	HTTPSRequired:                   {statusForbidden, "Saved passwords require HTTPS."},
	CredentialsDisabled:             {statusForbidden, "Saved passwords are turned off."},
	InvalidIntent:                   {statusConflict, "The confirmation has expired. Start again."},
	PreviewChanged:                  {statusConflict, "The target changed. Review it and try again."},
	CredentialInUse:                 {statusConflict, "The saved password is still assigned."},
	VaultLocked:                     {statusLocked, "The saved password changed. Start again."},
	InvalidTargets:                  {statusBadRequest, "The target is invalid."},
	CredentialTargetChanged:         {statusBadRequest, "The target changed since the password was assigned."},
	CredentialMissing:               {statusBadRequest, "No saved password is assigned."},
	CredentialUnreadable:            {statusBadRequest, "The saved password cannot be read."},
	CredentialUnavailable:           {statusBadRequest, "The saved password is unavailable."},
	StorageLimit:                    {statusBadRequest, "The storage limit is reached."},
	ReplacementConfirmationRequired: {statusBadRequest, "Confirm the replacement of the assigned password."},
	ConfirmationRequired:            {statusBadRequest, "Confirm the target to continue."},
	VaultMissing:                    {statusBadRequest, "There is no legacy vault to import."},
	VaultUnreadable:                 {statusBadRequest, "The legacy vault cannot be read."},
	VaultUnlockFailed:               {statusBadRequest, "The passphrase is wrong."},
	InvalidPassphrase:               {statusBadRequest, "The passphrase is invalid."},
	InvalidSchedule:                 {statusBadRequest, "The schedule is invalid."},
}

func init() {
	for c, e := range dataCatalog {
		if _, dup := catalog[c]; dup {
			panic(fmt.Sprintf("fault: code %q is in two catalogs", c))
		}
		catalog[c] = e
	}
}
