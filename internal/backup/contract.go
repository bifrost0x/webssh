package backup

import (
	"context"
	"io"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
)

// The contracts of the online backup, the restore and the secret rotation
// (C-BAK-01 to -09, docs/architecture/m2-contracts.md). The archive format
// above stays version 1; restore reads it strictly (D-30) and Python
// backups through LegacyRestorer.

// Owner is the schema owner of the backup tables (operations, restore
// status, one-time download tokens).
const Owner = "backup"

// OperationStatus is the state of an online backup operation, with the
// values of the Python release (backup_operations.py); the administration
// shows them.
type OperationStatus string

// Operation states.
const (
	StatusPending     OperationStatus = "pending"
	StatusRunning     OperationStatus = "running"
	StatusUploading   OperationStatus = "uploading"
	StatusVerifying   OperationStatus = "verifying"
	StatusVerified    OperationStatus = "verified"
	StatusReady       OperationStatus = "ready"
	StatusDownloading OperationStatus = "downloading"
	StatusRestoring   OperationStatus = "restoring"
	StatusFailed      OperationStatus = "failed"
)

// Active reports a state in which the operation holds the backup lock
// (_ACTIVE_STATUSES); cancel refuses those with fault.Conflict.
func (s OperationStatus) Active() bool {
	return slices.Contains([]OperationStatus{StatusPending, StatusRunning, StatusUploading,
		StatusVerifying, StatusDownloading, StatusRestoring}, s)
}

// RestoreState is the state of a restore that must survive a restart
// (maintenance_mode.py, A10). The Go file is the backup_restore table, not
// restore-status.json; the legacy file is only read by the migration.
type RestoreState string

// Restore states.
const (
	RestorePreparing      RestoreState = "preparing"
	RestoreInProgress     RestoreState = "in_progress"
	RestoreSucceeded      RestoreState = "succeeded"
	RestoreFailed         RestoreState = "failed"
	RestoreRollbackFailed RestoreState = "rollback_failed"
)

// Blocking reports a state in which the server stays in maintenance after a
// restart until the restore is finished or rolled back.
func (s RestoreState) Blocking() bool {
	return s == RestorePreparing || s == RestoreInProgress || s == RestoreRollbackFailed
}

// RestoreStatus is what GET /admin/api/backups/restore/status reports.
type RestoreStatus struct {
	OperationID string
	State       RestoreState
	StartedAt   time.Time
	FinishedAt  time.Time
	// Code is the fault code of a failed restore; never archive text.
	Code string
}

// ArchiveKind says which format an uploaded or named archive has.
type ArchiveKind string

// Archive kinds.
const (
	KindGo       ArchiveKind = "go"        // webssh-go-backup, this package
	KindPythonV1 ArchiveKind = "python-v1" // zip of the Python release, manifest version 1
	KindPythonV2 ArchiveKind = "python-v2" // zip of the Python release, manifest version 2
)

// Limits bound every archive a restore reads; the defaults and names are
// those of the Python release (BACKUP_MAX_*, BACKUP_UPLOAD_MAX_SIZE,
// BACKUP_OPERATION_TIMEOUT).
type Limits struct {
	MaxMembers          int
	MaxFileSize         int64
	MaxTotalSize        int64
	MaxCompressionRatio int
	MaxManifestSize     int64
	UploadMaxSize       int64
	OperationTimeout    time.Duration
}

// DefaultLimits are the defaults of config.py.
var DefaultLimits = Limits{
	MaxMembers: 10000, MaxFileSize: 1 << 30, MaxTotalSize: 10 << 30, MaxCompressionRatio: 200,
	MaxManifestSize: 10 << 20, UploadMaxSize: 1 << 30, OperationTimeout: 1800 * time.Second,
}

// LegacyRestore asks for a Python backup to be restored into a new Go
// database. Staging is an empty directory inside the Go-owned paths; the
// archive is read, never changed.
type LegacyRestore struct {
	Archive io.ReaderAt
	Size    int64
	Kind    ArchiveKind
	Staging string
	Limits  Limits
	// SecretKey is SECRET_KEY as resolved by I-08; a backup that carries
	// another data/secret_key is restored with the rules of the migration
	// specification (5.6), never by overwriting the environment value.
	SecretKey []byte
	// EnvironmentSecret says SECRET_KEY came from the environment. Only
	// then does it decrypt the legacy records of an archive that carries
	// its own data/secret_key (specification 5.6 step 4).
	EnvironmentSecret bool
	// Ring is the active keyring; the restored secrets are sealed with it.
	Ring *keyring.Ring
	// RecoverySnapshot keeps the remote credentials of the archive
	// (`backup restore --recovery-snapshot`); otherwise they are dropped
	// and the recovery check notice is set, as for an export.
	RecoverySnapshot bool
	// RestoredAt is the time of the restore (recovery check notice).
	RestoredAt time.Time
}

// Summary describes a verified archive the way the administration shows
// it (_archive_summary of the Python release).
type Summary struct {
	Kind                      ArchiveKind
	FormatVersion             int
	DataSchemaVersion         int
	CurrentDataSchemaVersion  int
	CreatedAt                 string
	Legacy                    bool
	FileCount                 int
	TotalUncompressedSize     int64
	Compatible                bool
	CompatibilityReason       string
	IncludesSecretKey         bool
	IncludesRemoteCredentials bool
}

// LegacyInspector verifies a Python backup without restoring it (the
// upload check and `webssh backup verify`), with the reading rules of the
// restore. Implemented beside LegacyRestorer in internal/migrate/legacy.
type LegacyInspector interface {
	InspectLegacy(ctx context.Context, archive io.ReaderAt, size int64, limits Limits) (Summary, error)
}

// LegacyOutcome is the result of a legacy restore: the staged database
// and the migration report, verified like the first migration.
type LegacyOutcome struct {
	Database string
	Report   string
}

// LegacyRestorer restores a Python backup through the same steps as the
// one-time migration (implemented in internal/migrate/legacy, connected in
// cmd/webssh; this package never imports it). An unsafe member (absolute
// path, "..", link, device, size or ratio over Limits) is fault.InvalidValue
// before anything is written.
type LegacyRestorer interface {
	RestoreLegacy(ctx context.Context, req LegacyRestore) (LegacyOutcome, error)
}

// Snapshotter writes a consistent copy of the live database while the
// server runs (internal/store, VACUUM INTO under the write lock).
type Snapshotter interface {
	Snapshot(ctx context.Context, path string) error
}

// MaintenanceReason says why the server is in maintenance.
type MaintenanceReason string

// Reasons for maintenance.
const (
	MaintenanceRestore      MaintenanceReason = "restore"
	MaintenanceRotation     MaintenanceReason = "rotation"
	MaintenanceSourceChange MaintenanceReason = "legacy_source_changed"
)

// Maintenance switches the server into maintenance (provided by
// cmd/webssh): /ready answers 503, every route except the probes answers
// 503 maintenance, realtime connections close with 4503 and new ones are
// refused. Enter fails with fault.Busy while another reason holds it;
// leave ends it unless the reason is legacy_source_changed, which only a
// restart ends.
type Maintenance interface {
	Enter(ctx context.Context, reason MaintenanceReason) (leave func(), err error)
	Active() (MaintenanceReason, bool)
}

// StepUp consumes the grants of the backup.* actions
// (internal/auth/stepup).
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}
