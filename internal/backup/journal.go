package backup

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// JournalName is the restore journal in the Go directory: the state of
// the last restore, which survives a restart (maintenance_mode.py,
// restore-status.json of the Python release). It holds no secret, only
// names of Go-owned files and key identifiers. It lives beside the
// database it describes, so that the restore of one data directory never
// acts on another (Python's data_fingerprint).
const JournalName = "restore-status.json"

const (
	journalFormat = 1
	maxJournal    = 16 << 10
)

// Journal is the persisted state of a restore.
type Journal struct {
	Format      int          `json:"format"`
	OperationID string       `json:"operation_id"`
	State       RestoreState `json:"state"`
	Kind        ArchiveKind  `json:"kind,omitempty"`
	// Staged is the staging directory's name in the Go directory.
	Staged string `json:"staged,omitempty"`
	// Material is the staged material file; MaterialPath the place it
	// replaces; PreviousMaterial where the replaced material is kept
	// until the restore is finished.
	Material         string `json:"material,omitempty"`
	MaterialPath     string `json:"material_path,omitempty"`
	PreviousMaterial string `json:"previous_material,omitempty"`
	KeyID            string `json:"key_id,omitempty"`
	// Secret says the staging directory holds the archive's SECRET_KEY,
	// which replaces DATA_DIR/secret_key (the replaced one is kept there
	// until the restore is finished).
	Secret    bool   `json:"secret,omitempty"`
	StartedAt string `json:"started_at"`
	UpdatedAt string `json:"updated_at"`
	Message   string `json:"message"`
	Code      string `json:"code,omitempty"`
}

// ErrJournal reports a journal that does not parse; it counts as a
// failed rollback (fail closed), as Python treats an unreadable status.
var ErrJournal = errors.New("backup: the restore journal is unreadable")

func journalPath(goDir string) string { return filepath.Join(goDir, JournalName) }

// ReadJournal returns the journal in goDir, or nil when there is none.
// An unreadable journal returns a rollback_failed journal and ErrJournal.
func ReadJournal(goDir string) (*Journal, error) {
	p := journalPath(goDir)
	info, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	unreadable := &Journal{Format: journalFormat, State: RestoreRollbackFailed, Message: "Restore status is unreadable"}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxJournal {
		return unreadable, errors.Join(ErrJournal, err)
	}
	f, err := os.Open(p) // #nosec G304 -- a fixed name in the Go directory
	if err != nil {
		return unreadable, errors.Join(ErrJournal, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxJournal+1))
	if err != nil || len(raw) > maxJournal {
		return unreadable, errors.Join(ErrJournal, err)
	}
	var j Journal
	if err := json.Unmarshal(raw, &j, json.RejectUnknownMembers(true)); err != nil || !j.valid() {
		return unreadable, errors.Join(ErrJournal, err)
	}
	return &j, nil
}

func (j *Journal) valid() bool {
	switch j.State {
	case RestorePreparing, RestoreInProgress, RestoreSucceeded, RestoreFailed, RestoreRollbackFailed:
	default:
		return false
	}
	if j.Format != journalFormat || !validOperationID(j.OperationID) || len(j.Message) > 256 {
		return false
	}
	if j.Staged != "" && j.Staged != stagedPrefix+j.OperationID {
		return false
	}
	return j.State != RestoreInProgress || j.Staged != ""
}

// writeJournal replaces the journal atomically: a temporary file in the
// Go directory, fsynced, renamed, and the directory fsynced.
func writeJournal(goDir string, j Journal, now time.Time) error {
	j.Format = journalFormat
	j.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	if j.StartedAt == "" {
		j.StartedAt = j.UpdatedAt
	}
	if len(j.Message) > 256 {
		j.Message = j.Message[:256]
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	tmp := filepath.Join(goDir, ".restore-status.tmp")
	if err := removeIfPresent(tmp); err != nil {
		return err
	}
	if err := writePrivate(tmp, raw); err != nil {
		return fmt.Errorf("backup: write the restore journal: %w", err)
	}
	if err := os.Rename(tmp, journalPath(goDir)); err != nil {
		return errors.Join(fmt.Errorf("backup: write the restore journal: %w", err), removeIfPresent(tmp))
	}
	return syncDir(goDir)
}

// Begin records that a restore of operationID is being prepared
// (preparing): a crash from here until Commit leaves the live state
// unchanged and the next start marks the restore failed.
func Begin(goDir, operationID string, now time.Time) error {
	if !validOperationID(operationID) {
		return errors.New("backup: invalid operation id")
	}
	return writeJournal(goDir, Journal{OperationID: operationID, State: RestorePreparing,
		Message: "Preparing the restore"}, now)
}

// Commit records a staged restore as in progress; from here on the next
// start of the installation activates it (Activate), so that the restore
// completes or is rolled back after any crash.
func Commit(goDir string, st Staged, in *Installation, now time.Time) error {
	j := Journal{OperationID: st.OperationID, State: RestoreInProgress, Kind: st.Kind, Staged: filepath.Base(st.Dir),
		KeyID: st.KeyID, Secret: st.Secret, Message: "Restoring persistent state"}
	if st.Material != "" {
		j.Material, j.MaterialPath = st.Material, in.MaterialPath
		j.PreviousMaterial = previousMaterialPath(in.MaterialPath, st.OperationID)
	}
	return writeJournal(goDir, j, now)
}

// Fail records a restore that failed before the live state changed.
func Fail(goDir, operationID, code string, now time.Time) error {
	return writeJournal(goDir, Journal{OperationID: operationID, State: RestoreFailed, Code: code,
		Message: "Restore failed before persistent state changed"}, now)
}

// Status is the public state of the last restore
// (GET /admin/api/backups/restore/status): idle without a journal, and
// idle again for a finished restore older than timeout.
func Status(goDir string, timeout time.Duration, now time.Time) (state, message string) {
	j, _ := ReadJournal(goDir)
	if j == nil {
		return "idle", ""
	}
	if !j.State.Blocking() {
		updated, err := time.Parse(time.RFC3339Nano, j.UpdatedAt)
		if err != nil || now.Sub(updated) > timeout {
			return "idle", ""
		}
	}
	return string(j.State), j.Message
}

// Blocked reports a restore that keeps the installation in maintenance:
// one that is unfinished or whose rollback failed, or an unreadable
// journal.
func Blocked(goDir string) (bool, string) {
	j, err := ReadJournal(goDir)
	if j == nil {
		return false, ""
	}
	if err != nil {
		return true, j.Message
	}
	return j.State.Blocking(), j.Message
}
