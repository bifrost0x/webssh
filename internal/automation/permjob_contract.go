package automation

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
)

// Limits of the permission jobs (app/permission_jobs.py).
const (
	PermMaxMembers   = 10000
	PermMaxDepth     = 64
	PermMaxNameBytes = 4 << 20
	PermScanTime     = 90 * time.Second
	PermApplyTime    = 300 * time.Second
	PermPreviewTTL   = 120 * time.Second
	PermTerminalTTL  = 120 * time.Second
	PermMaxRetained  = 64
	PermMaxExecuting = 2
	// permMetadataTTL is how long the metadata token of a single change is
	// accepted (METADATA_TTL of app/file_mutations.py).
	permMetadataTTL = 60 * time.Second
	// permMaxPath is FILE_CONTROL_MAX_PATH_BYTES at its upper bound.
	permMaxPath = 4096
)

// PermEntry is what lstat says about one object of a source.
type PermEntry struct {
	// Mode is the POSIX st_mode with the type bits.
	Mode    uint32
	Size    int64
	ModTime time.Time
	// UID and GID are nil when the server does not send them.
	UID, GID *uint32
}

// PermSource is one held file source that can change permissions (SFTP
// with lsetstat@openssh.com while the admin switch SFTP_CHMOD_ENABLED is
// on). Paths are canonical. Failures are *fault.Error with the upper-case
// file codes; Chmod never follows a link and verifies the result
// (MODE_MISMATCH, OUTCOME_UNKNOWN).
type PermSource interface {
	Lstat(ctx context.Context, path string) (PermEntry, error)
	// Children calls fn with the name of every entry of the directory.
	Children(ctx context.Context, dir string, fn func(name string) error) error
	Chmod(ctx context.Context, path string, perm uint32) error
}

// PermSources resolves the sources of the file workspace for permission
// changes (provided over internal/files in cmd/webssh).
type PermSources interface {
	// Hold returns the source for the principal if it belongs to the
	// principal's user and browser session, offers chmod and the admin
	// switch is on (UNSUPPORTED_OPERATION otherwise). identity changes
	// when the source was closed and opened again. release ends the hold.
	Hold(ctx context.Context, p principal.Principal, sourceID string) (src PermSource, identity any, release func(), err error)
	// Clean is the path rule of mutations (files.CleanTarget).
	Clean(path string) (string, error)
}

// PermQuotas reserves the background job quota (provided by
// internal/quota).
type PermQuotas interface {
	Reserve(ctx context.Context, kind string, userID, amount int64) (release func(), err error)
}

// PermAudit records permission changes as FILE_SOURCE_OPERATION events
// (operation chmod or chmod_job); the audit adds the source's target
// fields.
type PermAudit interface {
	PermissionChange(p principal.Principal, sourceID, operation, result, path, oldMode, newMode string)
}

// PermCaller identifies who asks: the principal and its realtime
// connection, which owns the jobs it prepared.
type PermCaller struct {
	P    principal.Principal
	Peer uint64
}
