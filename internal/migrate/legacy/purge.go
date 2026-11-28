package legacy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Checkpoints of a purge (section 5.9); a crash after each must be
// resolved by the next start or a repeated purge (I-25, I-26).
const (
	PointPurgeBackup   = "purge-backup-verified"
	PointPurgeStarted  = "purge-entry-written"
	PointPurgeRemoved  = "purge-file-removed"
	PointPurgeRecorded = "purge-entry-completed"
	PointPurgeMaterial = "purge-material-moved"
)

// PurgeOptions configure Purge. Registry is not needed.
type PurgeOptions struct {
	Options
	// BackupDir is --backup-to. Empty selects the parent of DATA_DIR when
	// it is writable, otherwise BackupTempDir.
	BackupDir string
	// SkipBackup is --skip-backup: no backup is written.
	SkipBackup bool
	// Backup writes the Go backup into req.Dir, verifies it by reading it
	// back and returns its path (internal/backup, wired by cmd/webssh).
	Backup func(ctx context.Context, req BackupRequest) (string, error)
	// Confirm is asked with the plan after every check and before
	// anything is written; false aborts with ErrPurgeAborted. Nil
	// proceeds (--yes).
	Confirm func(PurgePlan) bool
}

// BackupRequest is what the purge backup holds (section 5.9).
type BackupRequest struct {
	Dir string
	// Database is the cleanly closed Go database; it does not change
	// while the backup is written, because the purge holds the Go lock.
	Database string
	Secret   []byte
	Material []byte
	KeyID    string
	Release  string
	Now      time.Time
	// DataDir and Legacy are the legacy files the migration kept in place
	// that the purge removes (PurgePlan.KeptFiles); the backup holds them
	// too, relative to DataDir.
	DataDir string
	Legacy  []string
}

// Purged is the outcome of Purge.
type Purged struct {
	// State is the state the purge started in (S2, S5, S10 or S4).
	State State
	// Backup is the verified backup, "" with --skip-backup.
	Backup string
	// Removed counts the legacy files listed for removal.
	Removed  int
	Warnings []Warning
}

// Purge is `webssh legacy purge` (section 5.9). It is allowed in S2 after
// a migration, in S5 and to finish S10; in S4 it only completes the move
// of the keyring material. Before it removes anything it writes and
// verifies a Go backup with SECRET_KEY and the keyring material, unless
// SkipBackup is set; the backup also holds the legacy files the migration
// kept in place, and --skip-backup is refused while there are any. It
// refuses while the migration record lists legacy entities a later
// release migrates (pending, with a count above zero): removing them
// would lose them. The service must be stopped: the Go lock refuses it
// while Go serves.
func Purge(ctx context.Context, o PurgeOptions) (*Purged, error) {
	if o.DataDir == "" || o.Secret == "" {
		return nil, errors.New("legacy: purge needs the data directory and SECRET_KEY")
	}
	if !o.SkipBackup && o.Backup == nil {
		return nil, errors.New("legacy: purge needs a backup writer")
	}
	l, lock, warnings, err := lockAndClean(o.Options)
	if err != nil {
		return nil, err
	}
	defer lock.release()
	ev, err := evaluate(ctx, l, o.Secret)
	if err != nil {
		return nil, err
	}
	out := &Purged{State: ev.state, Warnings: append(warnings, ev.warnings...)}
	switch {
	case ev.state == S10:
		out.Backup, out.Removed = ev.purge.Backup, len(ev.purge.Files)
		return out, completePurge(ctx, l, o.Options, ev)
	case ev.state == S4:
		out.Backup = ev.purge.Backup
		return out, completePurge(ctx, l, o.Options, ev)
	case ev.stop != nil:
		return nil, ev.stop
	case ev.record == nil:
		return nil, stop(ev.state, CodePurgeRefused, "there is no migration record: this installation has no legacy data to purge", nil)
	case ev.state != S2 && ev.state != S5:
		return nil, stop(ev.state, CodePurgeRefused, "`webssh legacy purge` runs only after a migration", nil)
	}
	if err := refusePending(ev.record.Pending); err != nil {
		return nil, err
	}
	if ev.legacy != legacyNone {
		more, err := pythonIdle(l.dataDir, o.BackupTempDir)
		if err != nil {
			return nil, err
		}
		out.Warnings = append(out.Warnings, more...)
	}
	files := purgeList(ev.record.Listing)
	plan := planPurge(ev.record.Report, files, o.SkipBackup)
	if err := refuseUnsavedKept(ev.state, plan); err != nil {
		return nil, err
	}
	if o.Confirm != nil && !o.Confirm(plan) {
		return nil, ErrPurgeAborted
	}
	if !o.SkipBackup {
		if out.Backup, err = writePurgeBackup(ctx, l, o, ev, plan.KeptFiles); err != nil {
			return nil, err
		}
		o.at(PointPurgeBackup)
	}
	entry := purgeEntry{InProgress: true, Files: files, Backup: out.Backup,
		StartedAt: o.now().UTC().Format(time.RFC3339Nano)}
	out.Removed = len(entry.Files)
	if err := startPurge(ctx, l, entry); err != nil {
		return nil, stop(ev.state, CodePurgeFailed, "the purge entry could not be written; nothing was removed", err)
	}
	o.at(PointPurgeStarted)
	return out, completePurge(ctx, l, o.Options, ev)
}

// refusePending refuses while the record names entities this build left
// in place for a later release.
func refusePending(pending []Pending) error {
	names := pendingWithRecords(pending)
	if len(names) == 0 {
		return nil
	}
	return stop("", CodePurgeRefused, "the legacy data still holds data this release keeps in place for a later "+
		"release: "+strings.Join(names, ", ")+". A purge would delete it; run it after the release that migrates "+
		"these entities", nil)
}

// pendingWithRecords names the pending entities that hold records;
// pending entities without records lose nothing.
func pendingWithRecords(pending []Pending) []string {
	var names []string
	for _, p := range pending {
		if p.Count > 0 {
			names = append(names, fmt.Sprintf("%s (%d, phase %s)", p.Entity, p.Count, p.Phase))
		}
	}
	return names
}

// purgeList is the list of legacy files to remove: the files of the
// migration record, except secret_key, which holds SECRET_KEY for Go as
// well (I-08). logs/ and go/ are never part of the record.
func purgeList(listing []FileStat) []string {
	var files []string
	for _, f := range listing {
		if f.Path == "secret_key" || !filepath.IsLocal(filepath.FromSlash(f.Path)) {
			continue
		}
		top, _, _ := strings.Cut(f.Path, "/")
		if top == keyring.GoDirName || top == keyring.LogsDirName {
			continue
		}
		files = append(files, f.Path)
	}
	return files
}

// writePurgeBackup closes the database cleanly and lets o.Backup write
// and verify the backup.
func writePurgeBackup(ctx context.Context, l layout, o PurgeOptions, ev evaluation, kept []string) (string, error) {
	dir, err := purgeBackupDir(l, o)
	if err != nil {
		return "", stop(ev.state, CodePurgeBackup, "no directory for the backup; name one with --backup-to", err)
	}
	if err := closeCleanly(ctx, l.database); err != nil {
		return "", stop(ev.state, CodePurgeBackup, "the Go database could not be closed for the backup", err)
	}
	material, err := keyring.LoadOrCreateMaterial(l.dataDir, ev.legacy != legacyNone)
	if err != nil {
		return "", stop(ev.state, CodePurgeBackup, "the keyring material could not be read for the backup", err)
	}
	path, err := o.Backup(ctx, BackupRequest{Dir: dir, Database: l.database, Secret: []byte(o.Secret), Material: material,
		KeyID: ev.keyID, Release: o.Release, Now: o.now(), DataDir: l.dataDir, Legacy: kept})
	if err != nil {
		return "", stop(ev.state, CodePurgeBackup, "the backup could not be written and verified; nothing was removed", err)
	}
	return path, nil
}

// purgeBackupDir is --backup-to, or the parent of DATA_DIR when it is
// writable, or BACKUP_TEMP_DIR; never the Go directory or a path in it.
func purgeBackupDir(l layout, o PurgeOptions) (string, error) {
	var candidates []string
	if o.BackupDir != "" {
		candidates = []string{o.BackupDir}
	} else {
		candidates = []string{filepath.Dir(l.dataDir)}
		if o.BackupTempDir != "" {
			candidates = append(candidates, o.BackupTempDir)
		}
	}
	var errs []error
	for _, dir := range candidates {
		abs, err := filepath.Abs(dir)
		if err == nil && (abs == l.goDir || strings.HasPrefix(abs, l.goDir+string(filepath.Separator))) {
			err = errors.New("the backup must not be written into the Go directory")
		}
		if err == nil {
			err = writable(abs, o.BackupDir == "" && dir == o.BackupTempDir)
		}
		if err == nil {
			return abs, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", dir, err))
	}
	return "", errors.Join(errs...)
}

// writable checks dir by creating and removing a file in it; create makes
// a missing directory with mode 0700 first.
func writable(dir string, create bool) error {
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(dir, ".webssh-purge-check-")
	if err != nil {
		return err
	}
	return errors.Join(f.Close(), os.Remove(f.Name()))
}

func startPurge(ctx context.Context, l layout, e purgeEntry) error {
	db, err := store.Open(ctx, l.database, store.Options{})
	if err != nil {
		return err
	}
	err = db.ApplyAll(ctx, RecordSchema())
	if err == nil {
		err = db.Write(ctx, func(tx *store.Tx) error { return writePurgeStart(ctx, tx, e) })
	}
	return errors.Join(err, db.CloseForActivation(ctx))
}

// completePurge is section 5.9 steps 2 and 3 and the move of the keyring
// material. It continues a purge from its stored entry, so a start in S10
// and a repeated purge finish an interrupted one; every step is
// idempotent. Only files of the migration record's purge list are
// removed (recordedPurgeFiles).
func completePurge(ctx context.Context, l layout, o Options, ev evaluation) error {
	db, err := store.Open(ctx, l.database, store.Options{})
	if err != nil {
		return stop(S10, CodePurgeFailed, "the Go database could not be opened to complete the purge", err)
	}
	var recorded []string
	if ev.record != nil {
		recorded = purgeList(ev.record.Listing)
	}
	err = finishPurge(ctx, l, o, db, ev.keyID, recorded)
	return errors.Join(err, db.CloseForActivation(ctx))
}

// checkPurgeFiles refuses a purge entry that names a file outside the
// purge list of the migration record. The entry lives in the Go
// database; it must never remove secret_key, logs/, go/ or a file the
// migration did not record, whatever wrote it.
func checkPurgeFiles(files, recorded []string) error {
	allowed := make(map[string]bool, len(recorded))
	for _, f := range recorded {
		allowed[f] = true
	}
	for _, f := range files {
		if !allowed[f] {
			return fmt.Errorf("legacy: the purge entry names %q, which is not a recorded legacy file", f)
		}
	}
	return nil
}

func finishPurge(ctx context.Context, l layout, o Options, db *store.DB, keyID string, recorded []string) error {
	var e *purgeEntry
	err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		e, err = readPurge(ctx, tx)
		return err
	})
	if err != nil || e == nil {
		return stop(S10, CodePurgeFailed, "the purge entry could not be read", err)
	}
	if e.InProgress {
		if err := checkPurgeFiles(e.Files, recorded); err != nil {
			return stop(S7, CodeGoDatabase, "the purge entry of the Go database lists files the migration record does "+
				"not; nothing was removed. Restore the Go database from a backup", err)
		}
		if err := removeLegacyFiles(l.dataDir, e.Files, o); err != nil {
			return stop(S10, CodePurgeFailed, "a legacy file could not be removed; the purge continues at the next "+
				"start or with `webssh legacy purge`", err)
		}
		err := db.Write(ctx, func(tx *store.Tx) error {
			return writePurgeDone(ctx, tx, o.now().UTC().Format(time.RFC3339Nano))
		})
		if err != nil {
			return stop(S10, CodePurgeFailed, "the purge entry could not be completed", err)
		}
		o.at(PointPurgeRecorded)
	}
	if err := moveMaterialAfterPurge(ctx, l, o.Secret, db, keyID); err != nil {
		return stop(S4, CodeKeyMaterial, "the keyring material could not be moved into the Go directory; the next "+
			"start completes the move", err)
	}
	o.at(PointPurgeMaterial)
	return nil
}

// removeLegacyFiles removes the listed files below dataDir and syncs each
// affected directory. Paths are resolved inside dataDir with os.Root, so a
// link placed in the legacy tree cannot lead the removal outside it. A
// file that is already gone counts as removed.
func removeLegacyFiles(dataDir string, files []string, o Options) error {
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, f := range files {
		name := filepath.FromSlash(f)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("legacy: %q is not a path below the data directory", f)
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("legacy: remove %s: %w", f, err)
		}
		if err := syncRootDir(root, path.Dir(f)); err != nil {
			return err
		}
		o.at(PointPurgeRemoved)
	}
	return nil
}

func syncRootDir(root *os.Root, dir string) error {
	d, err := root.Open(filepath.FromSlash(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("legacy: sync %s: %w", dir, err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("legacy: sync %s: %w", dir, err)
	}
	return nil
}
