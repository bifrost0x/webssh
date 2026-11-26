package legacy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Replaced is the outcome of Replace.
type Replaced struct {
	Report     *Report
	ReportPath string
	// Database is where the replaced Go database was kept, or "" when
	// there was none.
	Database string
	Warnings []Warning
}

// Replace is `webssh migrate --replace` (section 5.4): it migrates the
// current legacy data again and replaces the Go database. It is the way
// out of S3, S1a and S9, and it also runs in S1 and S2. The service must be
// stopped: the Go lock refuses it while Go serves. It refuses a damaged Go
// database (S7) and a data directory without a complete legacy source.
//
// The replaced database is kept in go/replaced-<UTC>/ and named in the new
// record and the report. In M1 it is kept as a verified byte copy of the
// cleanly closed database; the Go backup format of internal/backup
// (D-03) replaces the copy once it exists. In S9 the database cannot be
// read, so it is moved there byte for byte together with every material
// file that does not match it, and new material is created afterwards, so
// that Go never creates material while a Go database exists (I-27).
func Replace(ctx context.Context, o Options) (*Replaced, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	l, lock, warnings, err := lockAndClean(o)
	if err != nil {
		return nil, err
	}
	defer lock.release()
	ev, err := evaluate(ctx, l, o.Secret)
	if err != nil {
		return nil, err
	}
	switch {
	case ev.legacy != legacyComplete:
		return nil, stop(ev.state, CodeReplaceNoLegacy, "there is no complete legacy source to migrate from", nil)
	case ev.state == S7:
		return nil, stop(S7, CodeReplaceDamaged, "the Go database is damaged; move it out of the Go directory by hand "+
			"(keep it as a backup) before running `webssh migrate --replace`", ev.stop)
	}
	out := &Replaced{Warnings: append(warnings, ev.warnings...)}
	r := &run{o: o, l: l}
	if ev.dbExists && ev.state != S9 {
		if r.extraSpace, err = databaseBytes(l); err != nil {
			return nil, stop(ev.state, CodeActivation, "the size of the current Go database cannot be read", err)
		}
	}
	// Every check comes before anything is set aside: a refusal must leave
	// the current database and its material where they are.
	if err := r.preflight(ctx); err != nil {
		r.writeFailure(err)
		return nil, err
	}
	if ev.dbExists {
		if out.Database, err = setAside(ctx, l, o, ev); err != nil {
			return nil, errors.Join(stop(ev.state, CodeActivation, "the current Go database could not be kept before the replacement", err), r.discard())
		}
		r.replaced = out.Database
		o.at(PointReplacedSaved)
	}
	if err := r.build(ctx); err != nil {
		r.writeFailure(err)
		return nil, err
	}
	path, more, err := r.activate(ctx)
	if err != nil {
		r.writeFailure(err)
		return nil, err
	}
	out.Report, out.ReportPath, out.Warnings = &r.report, path, append(out.Warnings, more...)
	return out, nil
}

// databaseBytes is the size of the Go database and its side files.
func databaseBytes(l layout) (int64, error) {
	var n int64
	for _, suffix := range append([]string{""}, sideFiles...) {
		info, err := os.Lstat(l.database + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		n += info.Size()
	}
	return n, nil
}

// setAside keeps the current database in a new replaced-<UTC>/ directory
// and returns the path of the kept copy.
func setAside(ctx context.Context, l layout, o Options, ev evaluation) (string, error) {
	dir, err := l.replacedDir(o.now())
	if err != nil {
		return "", err
	}
	kept := filepath.Join(dir, keyring.DatabaseName)
	if ev.state == S9 {
		return kept, moveUnreadable(l, dir, o.Secret, ev.keyID, o.now())
	}
	// Close the database cleanly, so that no -wal or -shm file belongs
	// to it (section 5.4 step 2), then keep a verified copy; the rename of
	// the activation replaces the original atomically.
	if err := closeCleanly(ctx, l.database); err != nil {
		return "", err
	}
	return kept, copyVerified(l.database, kept)
}

// moveUnreadable moves the database and its side files into dir, byte
// for byte (state S9), and every material file that does not match the
// database into logs/.webssh-go/replaced-<UTC>/. Material never goes into
// go/: go/ is part of every Python export, next to SECRET_KEY (I-22). A
// copy that matches the database stays where it is.
func moveUnreadable(l layout, dir, secret, keyID string, now time.Time) error {
	for _, suffix := range append([]string{""}, sideFiles...) {
		if err := moveIfPresent(l.database+suffix, filepath.Join(dir, keyring.DatabaseName+suffix)); err != nil {
			return err
		}
	}
	stateDir := ""
	for _, copy := range []struct{ path, name string }{
		{filepath.Join(l.goDir, keyring.MaterialName), "keyring-material-go"},
		{filepath.Join(l.stateDir, keyring.MaterialName), "keyring-material-logs"},
	} {
		material, err := os.ReadFile(copy.path) // #nosec G304 -- Go-owned material file
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil && keyID != "" {
			if ring, rerr := keyring.Open([]byte(secret), material); rerr == nil && ring.Verify(keyID) == nil {
				continue
			}
		}
		if stateDir == "" {
			if stateDir, err = l.stateReplacedDir(now); err != nil {
				return err
			}
		}
		if err := moveIfPresent(copy.path, filepath.Join(stateDir, copy.name)); err != nil {
			return err
		}
	}
	errs := []error{syncDir(dir), syncDir(l.goDir), syncDirIfPresent(l.stateDir)}
	if stateDir != "" {
		errs = append(errs, syncDir(stateDir))
	}
	return errors.Join(errs...)
}

func moveIfPresent(from, to string) error {
	if _, err := os.Lstat(from); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return os.Rename(from, to)
}

func syncDirIfPresent(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return syncDir(dir)
}

// closeCleanly opens the Go database and closes it in rollback-journal
// mode, which folds a WAL left by a crash into the file and leaves no side
// file.
func closeCleanly(ctx context.Context, path string) error {
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		return err
	}
	return db.CloseForActivation(ctx)
}
