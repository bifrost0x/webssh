package transfer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
)

// HTTP routes of a prepared transfer; <token> is the path value "token".
// They are those of the Python release (app/transfer_routes.py).
const (
	RouteDownload       = "GET /api/transfers/{token}/download"
	RouteFolderDownload = "GET /api/transfers/{token}/folder-download"
	RouteUpload         = "POST /api/transfers/{token}/upload"
)

// Direction of a transfer.
type Direction string

const (
	Upload         Direction = "upload"
	Download       Direction = "download"
	ServerToServer Direction = "server_to_server"
)

// State of a transfer.
type State string

const (
	Pending    State = "pending" // prepared, token not used yet
	Running    State = "running"
	Cancelling State = "cancelling"
	Cancelled  State = "cancelled"
	Failed     State = "failed"
	Completed  State = "completed"
)

// Terminal reports whether s is final.
func (s State) Terminal() bool { return s == Cancelled || s == Failed || s == Completed }

// CancelUnavailable is the cancel result for a transfer that does not
// exist for the caller (TransferCancelResult.state in Python).
const CancelUnavailable State = "unavailable"

// ConflictPolicy decides what happens when the destination exists. The
// Python release knows exactly these two; a download allows only
// ConflictError.
type ConflictPolicy string

const (
	ConflictError   ConflictPolicy = "error"   // fail with fault.FileConflict
	ConflictReplace ConflictPolicy = "replace" // replace atomically (files.StrategyAtomic)
)

// Tokens.
const (
	TokenTTL   = 300 * time.Second
	tokenBytes = 32
	TokenLen   = 43 // base64url without padding of tokenBytes
)

// NewToken returns a fresh token (secrets.token_urlsafe(32) in Python).
func NewToken() string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidToken reports whether s has the form of a token. A token of the
// wrong form is answered like an unknown one: 404 without a body.
func ValidToken(s string) bool {
	if len(s) != TokenLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Limits of transfers, with the defaults of the Python release.
type Limits struct {
	MaxUpload       int64 // MAX_UPLOAD_SIZE, 100 MiB
	MaxDownload     int64 // MAX_DOWNLOAD_SIZE, 100 MiB
	MaxArchive      int64 // MAX_ZIP_DOWNLOAD_SIZE, 500 MiB; also host-to-host copies
	MaxMembers      int   // MAX_TRANSFER_MEMBERS, 10000
	MaxDepth        int   // 50
	TempBytesPerUse int64 // QUOTA_TEMP_BYTES_PER_USER caps a ZIP being built, 512 MiB
}

// DefaultLimits are the limits of an unconfigured installation.
var DefaultLimits = Limits{
	MaxUpload: 100 << 20, MaxDownload: 100 << 20, MaxArchive: 500 << 20,
	MaxMembers: files.DefaultMaxMembers, MaxDepth: files.DefaultMaxDepth, TempBytesPerUse: 512 << 20,
}

// LimitKind names the limit a transfer exceeded.
type LimitKind string

const (
	LimitUpload         LimitKind = "upload"
	LimitDownload       LimitKind = "download"
	LimitArchive        LimitKind = "archive"
	LimitRemoteTransfer LimitKind = "remote_transfer"
)

// Failure is the public reason of a failed transfer, sent as
// {error_code, error, retryable[, limit_kind, limit_bytes, actual_bytes]}.
type Failure struct {
	Code        fault.Code
	Message     string // safe text; empty for the default of Code
	LimitKind   LimitKind
	LimitBytes  int64
	ActualBytes int64
}

// Retryable reports whether trying again may succeed (app/transfer_errors.py).
func (f Failure) Retryable() bool {
	switch f.Code {
	case fault.ShareUnavailable, fault.FileTimeout, fault.SourceUnavailable, fault.SourceChanged:
		return true
	}
	return false
}

// Progress is sent to the user's connections at most every 250 ms and once
// at the end (transfer_progress; s2s_transfer_progress for host-to-host).
type Progress struct {
	TransferID  string
	Direction   Direction
	Filename    string // base name, host-to-host only
	Transferred int64
	Total       int64
	Copy        *CopyRef // host-to-host only
}

// CopyRef correlates the events of a host-to-host copy with the request
// that started it (the members the page matches s2s_transfer_* on).
type CopyRef struct {
	SourceID, RequestID, DestinationSourceID string
}

// Finished is sent once per transfer (transfer_finished;
// s2s_transfer_complete or s2s_transfer_error).
type Finished struct {
	TransferID string
	Direction  Direction
	State      State // Completed, Cancelled or Failed
	Failure    *Failure
	// Host-to-host only: the correlation, the base name of the source and
	// both paths (s2s_transfer_complete).
	Copy                 *CopyRef
	Filename             string
	SourcePath, DestPath string
}

// Sources resolves a file source of the principal's browser session and
// holds it until release is called, so the source stays open while the
// transfer runs (provided by the files source registry). It fails with
// fault.SourceUnavailable for a source of another user or session, a
// closed one or one without need.
type Sources interface {
	Resolve(ctx context.Context, p principal.Principal, sourceID string, need files.Capability) (b files.Backend, release func(), err error)
}

// Quotas reserves runtime quota (provided by internal/quota). Kinds used
// here: "transfer" per HTTP transfer and "background_job" per host-to-host
// copy. A streamed ZIP uses no disk and charges no "temp_bytes".
type Quotas interface {
	Reserve(ctx context.Context, kind string, userID int64, amount int64) (release func(), err error)
}

// Events delivers progress to every realtime connection of the user
// (provided by the realtime wiring in cmd/webssh).
type Events interface {
	Progress(userID int64, ev Progress)
	Finished(userID int64, ev Finished)
}

// Active is one transfer as the admin operations page lists it: no
// token, no path.
type Active struct {
	ID        string
	UserID    int64
	Direction Direction
	State     State
	Started   time.Time
}
