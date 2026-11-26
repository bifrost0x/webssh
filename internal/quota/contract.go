package quota

import "errors"

// Kinds of runtime quota. The names are those of the Python release
// (QuotaKind in app/quota_manager.py); consumers pass them as plain
// strings, so their interfaces need no import of this package.
const (
	SSHSession      = "ssh_session"      // interactive terminal sessions
	QuickConnection = "quick_connection" // Quick SFTP and SMB sources
	Transfer        = "transfer"         // HTTP uploads and downloads
	TempBytes       = "temp_bytes"       // bytes of temporary files (ZIP archives)
	BackgroundJob   = "background_job"   // host-to-host copies, automation runs, permission jobs
)

// Kinds lists the quota kinds in a fixed order.
func Kinds() []string {
	return []string{SSHSession, QuickConnection, Transfer, TempBytes, BackgroundJob}
}

// Limit is the global and per-user bound of one kind, read from
// QUOTA_<KIND>_GLOBAL and QUOTA_<KIND>_PER_USER.
type Limit struct {
	Global, PerUser int64
}

// DefaultLimits are the limits of an unconfigured installation.
var DefaultLimits = map[string]Limit{
	SSHSession:      {Global: 10, PerUser: 5},
	QuickConnection: {Global: 12, PerUser: 3},
	Transfer:        {Global: 8, PerUser: 2},
	TempBytes:       {Global: 1 << 30, PerUser: 512 << 20},
	BackgroundJob:   {Global: 4, PerUser: 1},
}

// fairSlots are the kinds whose per-user limit must stay below the global
// one, so one user cannot take every slot.
var fairSlots = map[string]bool{SSHSession: true, QuickConnection: true, Transfer: true}

// ErrLimits reports limits that are not allowed.
var ErrLimits = errors.New("quota: per-user limit above the global limit")

// Check validates the limits of kind as the Python release did at start.
func (l Limit) Check(kind string) error {
	if l.Global < 1 || l.PerUser < 1 || l.PerUser > l.Global || fairSlots[kind] && l.PerUser == l.Global {
		return ErrLimits
	}
	return nil
}

// WithinStorage is the one rule of the storage limits (record and byte
// limits of saved connections and commands): a size up to limit is
// allowed, and a stored value already above it may stay as long as it
// does not grow (bounded_text in app/storage_quota.py).
func WithinStorage(size, stored, limit int64) bool {
	return size <= limit || stored >= 0 && size <= stored
}
