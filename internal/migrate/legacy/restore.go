package legacy

import (
	"slices"
	"time"
)

// RestoreMode selects which of Python's two restore paths an archive
// takes (app/backup_manager.py).
type RestoreMode int

const (
	// RestoreExport is restore_backup: an export, a CLI backup or an
	// online backup. Remote credentials in the archive are dropped and the
	// recovery check notice is set.
	RestoreExport RestoreMode = iota
	// RestoreRecoverySnapshot is a restore with --recovery-snapshot
	// (rollback.zip, *-pre-rotation-*.zip): credentials are kept.
	RestoreRecoverySnapshot
)

// transientTables are emptied by Python after every restore
// (app/restore_sanitizer.py _TRANSIENT_TABLES).
var transientTables = []string{
	"factor_bootstrap_tokens", "github_oauth_states", "oidc_login_states", "step_up_grants",
	"step_up_intents", "authentication_sessions", "pending_authentications", "webauthn_challenges",
	"totp_enrollments", "socket_sessions", "ssh_sessions",
}

type restoreState struct {
	mode       RestoreMode
	restoredAt time.Time
}

// Restored opens a directory that ExtractBackup wrote from a Python
// archive and applies, in memory, what Python does to the restored data
// before its next start (migration specification, section 5.6 step 3):
//
//   - every account's auth_generation is incremented, which invalidates
//     schedule approvals (app/restore_sanitizer.py); a database without the
//     column is left alone, as Python adds it later with default 0;
//   - the transient tables count as empty, so no persistent tmux session
//     (A01), browser session or pending enrolment is taken over;
//   - after an export, the recovery check notice reads as set at
//     restoredAt with remote credentials excluded (mark_restore_recovery).
//
// Use it together with PrivateCopy.
func Restored(mode RestoreMode, restoredAt time.Time) Option {
	return func(o *options) { o.restored = &restoreState{mode: mode, restoredAt: restoredAt.UTC()} }
}

func (s *Source) emptiedByRestore(table string) bool {
	return s.restored != nil && slices.Contains(transientTables, table)
}
