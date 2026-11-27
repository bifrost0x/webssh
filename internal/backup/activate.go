package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
)

// Checkpoints of an activation, in order; a crash after any of them must
// leave a state the next Activate completes or rolls back.
const (
	PointPreviousKept      = "previous-database-kept"
	PointDatabaseRenamed   = "database-renamed"
	PointPreviousMaterial  = "previous-material-kept"
	PointMaterialInstalled = "material-installed"
	PointPreviousSecret    = "previous-secret-kept"
	PointSecretInstalled   = "secret-installed"
	PointJournalDone       = "journal-finished"
)

const (
	previousDBName = "previous.db"
	failedDBName   = "restored.db"
)

var sideSuffixes = []string{"-wal", "-shm", "-journal"}

// Activate completes the restore the journal in dataDir records. It runs
// at every start before the Go database is opened, with the Go lock
// held, and in `webssh backup restore`. A restore in progress is
// activated (the staged database renamed into place, the staged material
// installed); if that fails, the previous database and material are put
// back (failed), and if that fails too, the journal says rollback_failed
// and the installation stays in maintenance. A restore that was still
// being prepared changed nothing and is marked failed. Staging leftovers
// of finished restores are removed. It returns the journal, or nil.
func Activate(dataDir string, now func() time.Time) (*Journal, error) {
	return activate(dataDir, now, func(string) {})
}

func activate(dataDir string, now func() time.Time, point func(string)) (*Journal, error) {
	goDir := filepath.Join(dataDir, keyring.GoDirName)
	j, err := ReadJournal(goDir)
	if j == nil || err != nil {
		return j, err
	}
	switch j.State {
	case RestorePreparing:
		if err := removeStaged(dataDir, goDir, j.OperationID); err != nil {
			return j, err
		}
		j.State, j.Message, j.Code = RestoreFailed, "Restore stopped before persistent state changed", "restore_interrupted"
		return j, writeJournal(goDir, *j, now())
	case RestoreInProgress:
	default:
		return j, removeStale(dataDir, goDir, j)
	}
	if err := checkJournalPaths(dataDir, j); err != nil {
		j.State, j.Message, j.Code = RestoreRollbackFailed, "Interrupted restore has no safe reference; use the CLI recovery path", "restore_unsafe_journal"
		return j, errors.Join(err, writeJournal(goDir, *j, now()))
	}
	applyErr := apply(dataDir, goDir, j, point)
	if applyErr == nil {
		j.State, j.Message, j.Code = RestoreSucceeded, "Restore completed; WebSSH restarted with the restored data", ""
		if err := keepReport(goDir, filepath.Join(goDir, j.Staged), now()); err != nil {
			// The restore itself succeeded; the journal says what is missing.
			j.Message += "; the migration report of the archive could not be kept: " + err.Error()
		}
		if err := writeJournal(goDir, *j, now()); err != nil {
			return j, err
		}
		point(PointJournalDone)
		return j, removeStale(dataDir, goDir, j)
	}
	if err := rollback(dataDir, goDir, j); err != nil {
		j.State, j.Message, j.Code = RestoreRollbackFailed,
			"Restore failed and the rollback failed; restore a backup with `webssh backup restore`", "restore_rollback_failed"
		return j, errors.Join(applyErr, err, writeJournal(goDir, *j, now()))
	}
	j.State, j.Message, j.Code = RestoreFailed, "Restore failed; original state was restored", "restore_failed"
	return j, errors.Join(applyErr, writeJournal(goDir, *j, now()), removeStale(dataDir, goDir, j))
}

// keepReport moves the migration report of a restored Python archive from
// the staging directory into the Go directory, next to the report of the
// first migration. A Go archive has none.
func keepReport(goDir, staged string, now time.Time) error {
	from := filepath.Join(staged, stagedReportName)
	if !exists(from) {
		return nil
	}
	return moveFile(from, filepath.Join(goDir, restoreReportPrefix+now.UTC().Format("20060102T150405.000000000Z")+".json"))
}

// checkJournalPaths accepts only the paths Commit writes.
func checkJournalPaths(dataDir string, j *Journal) error {
	if j.Material == "" {
		if j.MaterialPath != "" || j.PreviousMaterial != "" {
			return errors.New("backup: the journal names material paths without material")
		}
		return nil
	}
	location, _, err := keyring.MaterialLocation(dataDir, false)
	if err != nil && !errors.Is(err, keyring.ErrMaterialConflict) {
		return err
	}
	inGo := filepath.Join(dataDir, keyring.GoDirName, keyring.MaterialName)
	inState := filepath.Join(dataDir, keyring.LogsDirName, keyring.StateDirName, keyring.MaterialName)
	switch {
	case j.MaterialPath != inGo && j.MaterialPath != inState && j.MaterialPath != location:
		return errors.New("backup: the journal names an unknown material location")
	case j.Material != stagedMaterialPath(j.MaterialPath, j.OperationID),
		j.PreviousMaterial != previousMaterialPath(j.MaterialPath, j.OperationID):
		return errors.New("backup: the journal names unexpected material files")
	}
	return nil
}

func apply(dataDir, goDir string, j *Journal, point func(string)) error {
	db := filepath.Join(goDir, keyring.DatabaseName)
	dir := filepath.Join(goDir, j.Staged)
	staged := filepath.Join(dir, keyring.DatabaseName)
	prev := filepath.Join(dir, previousDBName)
	if exists(staged) {
		if exists(db) && !exists(prev) {
			// Side files belong to the database they are next to; they go
			// with it, never onto the restored one.
			for _, s := range sideSuffixes {
				if exists(db + s) {
					if err := os.Rename(db+s, prev+s); err != nil {
						return fmt.Errorf("backup: keep %s: %w", db+s, err)
					}
				}
			}
			if err := os.Rename(db, prev); err != nil {
				return fmt.Errorf("backup: keep the previous database: %w", err)
			}
			point(PointPreviousKept)
		}
		for _, s := range sideSuffixes {
			if exists(db + s) {
				return fmt.Errorf("backup: %s is still beside the database", db+s)
			}
		}
		if err := os.Rename(staged, db); err != nil {
			return fmt.Errorf("backup: activate the restored database: %w", err)
		}
		if err := syncDir(goDir); err != nil {
			return err
		}
	}
	point(PointDatabaseRenamed)
	if err := applyMaterial(dataDir, j, point); err != nil {
		return err
	}
	return applySecret(dataDir, dir, j, point)
}

// applyMaterial installs the staged keyring material, keeping the
// replaced one for a rollback.
func applyMaterial(dataDir string, j *Journal, point func(string)) error {
	if j.Material == "" || !exists(j.Material) {
		return nil
	}
	current, err := keyring.ReadMaterialFile(j.MaterialPath)
	if err != nil {
		return err
	}
	if current != nil && !exists(j.PreviousMaterial) {
		if err := writePrivate(j.PreviousMaterial, current); err != nil {
			return fmt.Errorf("backup: keep the previous material: %w", err)
		}
	}
	point(PointPreviousMaterial)
	material, err := keyring.ReadMaterialFile(j.Material)
	if err != nil || material == nil {
		return errors.Join(errors.New("backup: the staged material is unreadable"), err)
	}
	if err := keyring.InstallMaterial(dataDir, j.MaterialPath, material); err != nil {
		return err
	}
	point(PointMaterialInstalled)
	return removeIfPresent(j.Material)
}

// applySecret installs the archive's SECRET_KEY as DATA_DIR/secret_key,
// keeping the replaced file in the staging directory for a rollback. A
// staged secret that is gone was installed by an earlier attempt.
func applySecret(dataDir, dir string, j *Journal, point func(string)) error {
	staged := filepath.Join(dir, stagedSecretName)
	if !j.Secret || !exists(staged) {
		return nil
	}
	file := filepath.Join(dataDir, secretFileName)
	prev := filepath.Join(dir, previousSecretName)
	current, err := readSecretFile(file)
	if err != nil {
		return err
	}
	if current != nil && !exists(prev) {
		if err := writePrivate(prev, current); err != nil {
			return fmt.Errorf("backup: keep the previous SECRET_KEY: %w", err)
		}
	}
	point(PointPreviousSecret)
	secret, err := readSecretFile(staged)
	if err != nil || secret == nil {
		return errors.Join(errors.New("backup: the staged SECRET_KEY is unreadable"), err)
	}
	if err := installSecretFile(file, secret); err != nil {
		return err
	}
	point(PointSecretInstalled)
	return removeRegular(staged)
}

// rollback puts back the previous database and material of an activation
// that failed.
func rollback(dataDir, goDir string, j *Journal) error {
	db := filepath.Join(goDir, keyring.DatabaseName)
	dir := filepath.Join(goDir, j.Staged)
	prev := filepath.Join(dir, previousDBName)
	stagedLeft := exists(filepath.Join(dir, keyring.DatabaseName))
	if !exists(prev) && !stagedLeft && exists(db) {
		// The installation had no database: the restored one goes aside.
		if err := os.Rename(db, filepath.Join(dir, failedDBName)); err != nil {
			return err
		}
	}
	if exists(prev) {
		if exists(db) && !stagedLeft {
			if err := os.Rename(db, filepath.Join(dir, failedDBName)); err != nil {
				return err
			}
		}
		if err := os.Rename(prev, db); err != nil {
			return fmt.Errorf("backup: put back the previous database: %w", err)
		}
		for _, s := range sideSuffixes {
			if exists(prev + s) {
				if err := os.Rename(prev+s, db+s); err != nil {
					return err
				}
			}
		}
		if err := syncDir(goDir); err != nil {
			return err
		}
	}
	if prev := filepath.Join(dir, previousSecretName); j.Secret && exists(prev) {
		secret, err := readSecretFile(prev)
		if err != nil || secret == nil {
			return errors.Join(errors.New("backup: the previous SECRET_KEY is unreadable"), err)
		}
		if err := installSecretFile(filepath.Join(dataDir, secretFileName), secret); err != nil {
			return err
		}
	}
	if j.PreviousMaterial != "" && exists(j.PreviousMaterial) {
		material, err := keyring.ReadMaterialFile(j.PreviousMaterial)
		if err != nil || material == nil {
			return errors.Join(errors.New("backup: the previous material is unreadable"), err)
		}
		if err := keyring.InstallMaterial(dataDir, j.MaterialPath, material); err != nil {
			return err
		}
	}
	return nil
}

// removeStaged removes everything Stage may have written for an
// operation: the staging directory and staged material in either
// material location.
func removeStaged(dataDir, goDir, operationID string) error {
	errs := []error{os.RemoveAll(filepath.Join(goDir, stagedPrefix+operationID))}
	for _, dir := range []string{goDir, filepath.Join(dataDir, keyring.LogsDirName, keyring.StateDirName)} {
		errs = append(errs, removeIfPresent(stagedMaterialPath(filepath.Join(dir, keyring.MaterialName), operationID)))
	}
	return errors.Join(errs...)
}

// removeStale removes the staging leftovers of finished restores: every
// .restore-* entry of the Go directory and of the state directory. Only
// a restore in progress (or one whose rollback failed) keeps its files.
func removeStale(dataDir, goDir string, j *Journal) error {
	if j.State.Blocking() {
		return nil
	}
	var errs []error
	for _, dir := range []string{goDir, filepath.Join(dataDir, keyring.LogsDirName, keyring.StateDirName)} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), stagedPrefix) {
				errs = append(errs, os.RemoveAll(filepath.Join(dir, e.Name())))
			}
		}
	}
	return errors.Join(errs...)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
