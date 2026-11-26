package legacy

import (
	"errors"
	"fmt"
)

// State is a state of the start-up state machine (migration
// specification, section 5.1).
type State string

// States of section 5.1. S4 and S10 need `webssh legacy purge`, which a
// later phase adds; until then no database can be in them and the purge
// is refused.
const (
	S0  State = "S0"  // fresh: no legacy source, no Go database
	S1  State = "S1"  // legacy only: migrate
	S1a State = "S1a" // legacy present, Go data missing, marker present: STOP
	S2  State = "S2"  // migrated (or a Go-native database): start
	S3  State = "S3"  // legacy changed since the migration: STOP
	S4  State = "S4"  // legacy purged: start
	S5  State = "S5"  // legacy missing without a purge: start with a warning
	S6  State = "S6"  // interrupted: staging removed, evaluated again
	S7  State = "S7"  // unknown or damaged: STOP
	S9  State = "S9"  // keyring material missing or not matching: STOP
	S10 State = "S10" // purge in progress
)

// Stop codes. They are stable: the CLI, the log and the report use them.
const (
	CodeLocked          = "go_locked"
	CodeLegacyChanged   = "legacy_changed"
	CodeGoDataMissing   = "go_data_missing"
	CodeGoDatabase      = "go_database_unusable"
	CodeLegacyUnknown   = "legacy_source_unknown"
	CodeKeyMaterial     = "keyring_material"
	CodeLegacyInUse     = "legacy_in_use"
	CodeRestorePending  = "python_restore_unfinished"
	CodeNoSpace         = "not_enough_space"
	CodeSecretMismatch  = "secret_key_mismatch"
	CodeChangedDuring   = "legacy_changed_during_migration"
	CodeUnsafeSource    = "legacy_unsafe_path"
	CodeUnreadable      = "legacy_unreadable"
	CodeStepFailed      = "migration_step_failed"
	CodeVerifyFailed    = "migration_verification_failed"
	CodeActivation      = "activation_failed"
	CodeReplaceDamaged  = "replace_refused_damaged_database"
	CodeReplaceNoLegacy = "replace_without_legacy_source"
)

// ErrLocked reports that another Go process holds the Go lock.
var ErrLocked = errors.New("legacy: another WebSSH process holds the Go lock")

// StopError is a STOP of the migration specification: Go does not start,
// nothing was changed, and the message says what to do. It names the
// entity, user and record where one is involved, never a secret value.
type StopError struct {
	State   State
	Code    string
	Entity  string
	UserID  int64
	Record  string
	Message string
	Err     error
}

func (e *StopError) Error() string {
	where := ""
	if e.Entity != "" {
		where = " [" + e.Entity
		if e.UserID != 0 {
			where += fmt.Sprintf(" user %d", e.UserID)
		}
		if e.Record != "" {
			where += " record " + e.Record
		}
		where += "]"
	}
	msg := e.Message
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	if e.State != "" {
		return fmt.Sprintf("migration stopped (%s, %s)%s: %s", e.State, e.Code, where, msg)
	}
	return fmt.Sprintf("migration stopped (%s)%s: %s", e.Code, where, msg)
}

func (e *StopError) Unwrap() error { return e.Err }

func stop(state State, code, message string, err error) *StopError {
	return &StopError{State: state, Code: code, Message: message, Err: err}
}

// StepError lets a step name the user and record that failed. The
// framework turns it into a StopError for the step's entity.
type StepError struct {
	UserID int64
	Record string
	Err    error
}

func (e *StepError) Error() string { return e.Err.Error() }
func (e *StepError) Unwrap() error { return e.Err }

// ErrSecretMismatch reports a SECRET_KEY that does not decrypt the
// legacy data (A02).
var ErrSecretMismatch = errors.New("legacy: SECRET_KEY does not match the stored data")
