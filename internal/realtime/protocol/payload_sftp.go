package protocol

// Payloads of the SFTP sources (internal/files/sftp): Quick SFTP and the
// terminal session's own file source. The requests carry the members the
// pages send today (sftp-file-manager.js, session-workspace.js,
// session-directory-sync.js); the shim turns the results into the events
// of today.

// Message types of the SFTP sources (FS2).
const (
	TypeFilesQuickOpen        = "files.quick.open"
	TypeFilesQuickClose       = "files.quick.close"
	TypeFilesSessionProbe     = "files.session.probe"
	TypeFilesSessionDirectory = "files.session.directory"
)

// FilesQuickOpen connects Quick SFTP (quick_connect): the target fields of
// terminal.open and the request id that correlates the answer and the
// host-key prompt.
type FilesQuickOpen struct {
	OpenTarget
	ClientRequestID string `json:"client_request_id,omitzero"`
}

// FilesQuickOpened is the result of files.quick.open
// (quick_connect_success).
type FilesQuickOpened struct {
	ClientRequestID string     `json:"client_request_id"`
	ConnectionID    string     `json:"connection_id"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	Username        string     `json:"username"`
	FileSource      FileSource `json:"file_source"`
}

// FilesQuickClose closes a Quick SFTP connection (quick_disconnect).
type FilesQuickClose struct {
	ConnectionID string `json:"connection_id"`
}

// FilesQuickClosed is the result of files.quick.close
// (quick_disconnect_success).
type FilesQuickClosed struct {
	ConnectionID string `json:"connection_id"`
}

// FilesSessionProbe asks whether an owned terminal session can browse
// files (probe_session_sftp).
type FilesSessionProbe struct {
	SessionID string `json:"session_id"`
	RequestID string `json:"request_id"`
}

// FilesSessionCapability is the result of files.session.probe
// (session_sftp_capability). Reason is resource_shortage when the server
// refused the channel.
type FilesSessionCapability struct {
	SessionID string `json:"session_id"`
	RequestID string `json:"request_id"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitzero"`
}

// FilesSessionDirectoryRequest asks for the directory of a session's shell
// (request_session_directory).
type FilesSessionDirectoryRequest struct {
	SessionID string `json:"session_id"`
}

// FilesSessionDirectory is the result of files.session.directory: the
// directory, or none and the reason of today (unavailable, unsupported,
// busy, disconnected).
type FilesSessionDirectory struct {
	Directory *SessionDirectory `json:"directory"`
	Reason    *string           `json:"reason"`
}

// SessionDirectory is the probe's answer (collect_directory).
type SessionDirectory struct {
	Path           string        `json:"path"`
	ShellReady     bool          `json:"shell_ready"`
	ShellID        string        `json:"shell_id"`
	Shell          string        `json:"shell"`
	BracketedPaste *bool         `json:"bracketed_paste,omitempty"`
	Prompt         *PromptMarker `json:"prompt,omitempty"`
	InputIdle      bool          `json:"input_idle"`
	Tmux           bool          `json:"tmux,omitzero"`
}

// PromptMarker is the prompt marker of a bash inside tmux.
type PromptMarker struct {
	Generation int    `json:"generation"`
	Phase      string `json:"phase"`
}
