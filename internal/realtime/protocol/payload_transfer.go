package protocol

// Payloads of transfer.* (internal/transfer). The requests carry the
// members the pages send today (binary-transfer-client.js,
// sftp-file-manager.js); the results and events carry the members of the
// Python acknowledgements and push events (prepare_transfer,
// cancel_transfer, transfer_server_to_server, transfer_progress,
// transfer_finished, s2s_transfer_*). The shim builds those from them.

// Message types of the area "transfer" (TR1).
const (
	TypeTransferPrepare  = "transfer.prepare"
	TypeTransferCancel   = "transfer.cancel"
	TypeTransferCopy     = "transfer.copy"
	TypeTransferProgress = "transfer.progress"
	TypeTransferFinished = "transfer.finished"
)

// TransferPrepare asks for a one-use URL of an HTTP upload or download
// (prepare_transfer). ConflictPolicy is "error" (default) or "replace",
// replace only for an upload; Archive asks for a folder as ZIP.
type TransferPrepare struct {
	FileRef
	Direction      string `json:"direction"`
	RemotePath     string `json:"remote_path"`
	Archive        bool   `json:"archive,omitzero"`
	ConflictPolicy string `json:"conflict_policy,omitzero"`
}

// TransferPrepared is the result of transfer.prepare: the URL below the
// application root, valid once until ExpiresAt (Unix seconds).
type TransferPrepared struct {
	FileRef
	TransferID string  `json:"transfer_id"`
	URL        string  `json:"url"`
	ExpiresAt  float64 `json:"expires_at"`
	Direction  string  `json:"direction"`
}

// TransferCancel cancels a transfer of the user (cancel_transfer).
type TransferCancel struct {
	TransferID string `json:"transfer_id"`
}

// TransferCancelState is the result of transfer.cancel: cancelling,
// cancelled, completed, failed or unavailable (a transfer the caller does
// not own or that is gone).
type TransferCancelState struct {
	State string `json:"state"`
}

// TransferCopy starts a host-to-host copy (transfer_server_to_server).
type TransferCopy struct {
	FileRef
	SourcePath          string `json:"source_path"`
	DestinationSourceID string `json:"destination_source_id"`
	DestPath            string `json:"dest_path"`
	IsDir               bool   `json:"is_dir,omitzero"`
	ConflictPolicy      string `json:"conflict_policy,omitzero"`
}

// TransferCopyStarted is the result of transfer.copy.
type TransferCopyStarted struct {
	FileRef
	TransferID          string `json:"transfer_id"`
	DestinationSourceID string `json:"destination_source_id"`
}

// TransferCopyRef correlates the events of a host-to-host copy with the
// request that started it.
type TransferCopyRef struct {
	SourceID            string `json:"source_id"`
	RequestID           string `json:"request_id"`
	DestinationSourceID string `json:"destination_source_id"`
}

// TransferProgressEvent is sent at most every 250 ms per transfer and once
// at the end. Copy is set for a host-to-host copy (s2s_transfer_progress),
// with the base name of the file being copied.
type TransferProgressEvent struct {
	TransferID  string           `json:"transfer_id"`
	Direction   string           `json:"direction"`
	Transferred int64            `json:"transferred"`
	Total       int64            `json:"total"`
	Filename    string           `json:"filename,omitzero"`
	Copy        *TransferCopyRef `json:"copy,omitzero"`
}

// TransferFinishedEvent is sent once per transfer. Status is completed,
// cancelled or failed; a failure carries the public reason of
// app/transfer_errors.py. A host-to-host copy carries Copy, the base name
// and both paths (s2s_transfer_complete, s2s_transfer_error).
type TransferFinishedEvent struct {
	TransferID  string           `json:"transfer_id"`
	Direction   string           `json:"direction,omitzero"`
	Status      string           `json:"status"`
	ErrorCode   string           `json:"error_code,omitzero"`
	Error       string           `json:"error,omitzero"`
	Retryable   *bool            `json:"retryable,omitzero"`
	LimitKind   string           `json:"limit_kind,omitzero"`
	LimitBytes  *int64           `json:"limit_bytes,omitzero"`
	ActualBytes *int64           `json:"actual_bytes,omitzero"`
	Copy        *TransferCopyRef `json:"copy,omitzero"`
	Filename    string           `json:"filename,omitzero"`
	SourcePath  string           `json:"source_path,omitzero"`
	DestPath    string           `json:"dest_path,omitzero"`
}
