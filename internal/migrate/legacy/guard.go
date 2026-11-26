package legacy

import (
	"errors"
	"path/filepath"
)

// pythonIdle runs the checks of section 5.2 step 4 that refuse to migrate
// beside a running Python release: a SQLite lock on app.db, a held backup
// operation lock and an unfinished restore (A10). They catch Python in the
// middle of a transaction or a backup operation; an idle Python holds no
// lock, so the decisive guard is the second digest comparison before
// activation. A hot journal is checked when the source is opened. Nothing
// is written. Checks this platform cannot run are returned as warnings.
func pythonIdle(dataDir, backupTempDir string) ([]Warning, error) {
	var warnings []Warning
	held, err := probeSQLiteLock(filepath.Join(dataDir, "app.db"))
	switch {
	case errors.Is(err, errProbeUnsupported):
		warnings = append(warnings, Warning{Code: "sqlite_lock_not_checked", Message: err.Error()})
	case err != nil:
		return nil, stop("", CodeLegacyInUse, "the lock of app.db could not be checked", err)
	case held:
		return nil, stop("", CodeLegacyInUse, "another process holds a lock on app.db; stop the Python release before the upgrade", nil)
	}
	if backupTempDir == "" {
		return append(warnings, Warning{Code: "python_operations_not_checked",
			Message: "BACKUP_TEMP_DIR is unknown, so a running Python backup or restore was not checked"}), nil
	}
	namespace, err := BackupNamespace(backupTempDir, dataDir)
	if err != nil {
		return nil, stop("", CodeLegacyInUse, "the Python backup operation directory could not be resolved", err)
	}
	held, err = probeFlock(filepath.Join(namespace, "operation.lock"))
	switch {
	case errors.Is(err, errProbeUnsupported):
		warnings = append(warnings, Warning{Code: "python_operation_lock_not_checked", Message: err.Error()})
	case err != nil:
		return nil, stop("", CodeLegacyInUse, "the Python backup operation lock could not be checked", err)
	case held:
		return nil, stop("", CodeLegacyInUse, "a Python backup or restore is running; wait for it to finish and stop the Python release", nil)
	}
	status, err := ReadRestoreStatus(namespace)
	if err != nil {
		return nil, stop("", CodeRestorePending, "the Python restore status could not be read", err)
	}
	if status.Unfinished() {
		return nil, stop("", CodeRestorePending, "a Python restore is unfinished (state "+status.State+
			"); finish or roll back the restore with the Python release before the upgrade", nil)
	}
	return warnings, nil
}
