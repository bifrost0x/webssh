package legacy

import (
	"context"
	"errors"
	"strings"
)

// Startup is the outcome of Start for a data directory Go may serve. It
// holds the Go lock until Close, so that `webssh migrate --replace` and a
// second server refuse to run beside this one.
type Startup struct {
	State State
	// Migrated reports that this start migrated the legacy data; Report
	// and ReportPath describe that migration.
	Migrated   bool
	Report     *Report
	ReportPath string
	// Warnings are shown at every start in this state (for example S5).
	Warnings []Warning
	lock     *goLock
}

// Close releases the Go lock.
func (s *Startup) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.release()
	s.lock = nil
	return err
}

// Start runs the start-up sequence of section 5.1 for the data directory:
// it takes the Go lock, removes leftover staging directories (S6),
// evaluates the state and migrates in S1 (section 5.2). States that must
// not start (S1a, S3, S7, S9) return a *StopError naming the way out;
// nothing was changed then except Go-owned files the specification lets
// Go repair.
func Start(ctx context.Context, o Options) (*Startup, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	l, lock, warnings, err := lockAndClean(o)
	if err != nil {
		return nil, err
	}
	if o.BeforeStart != nil {
		if err := o.BeforeStart(ctx); err != nil {
			return nil, errors.Join(err, lock.release())
		}
	}
	st, err := start(ctx, o, l, warnings)
	if err != nil {
		return nil, errors.Join(err, lock.release())
	}
	st.lock = lock
	return st, nil
}

func start(ctx context.Context, o Options, l layout, warnings []Warning) (*Startup, error) {
	ev, err := evaluate(ctx, l, o.Secret)
	if err != nil {
		return nil, err
	}
	st := &Startup{State: ev.state, Warnings: append(warnings, ev.warnings...)}
	switch {
	case ev.stop != nil && ev.state == S9 && ev.legacy == legacyComplete:
		if se := legacySecretStop(ctx, l.dataDir, o.Secret); se != nil {
			return nil, se
		}
		return nil, ev.stop
	case ev.stop != nil:
		return nil, ev.stop
	case ev.state == S1 && o.RequireCoverage && len(o.Registry.Uncovered()) > 0:
		return nil, stop(S1, CodeIncompleteBuild, "this build does not migrate every kind of legacy data ("+
			strings.Join(o.Registry.Uncovered(), ", ")+"); nothing was changed. Start a release that migrates them", nil)
	case ev.state == S10 || ev.state == S4:
		// Finish an interrupted purge from its stored list, and the move
		// of the keyring material into go/ (section 5.9).
		if err := completePurge(ctx, l, o, ev.keyID); err != nil {
			return nil, err
		}
		if ev.state == S10 {
			st.State = S4
			st.Warnings = append(st.Warnings, Warning{Code: "purge_completed",
				Message: "an interrupted `webssh legacy purge` was completed"})
		}
	case ev.state == S1:
		r := &run{o: o, l: l}
		if err := r.migrate(ctx); err != nil {
			r.writeFailure(err)
			return nil, err
		}
		path, more, err := r.activate(ctx)
		if err != nil {
			r.writeFailure(err)
			return nil, err
		}
		st.State, st.Migrated, st.Report, st.ReportPath = S2, true, &r.report, path
		st.Warnings = append(st.Warnings, more...)
	case ev.state == S2 && ev.record != nil && ev.legacy != legacyNone &&
		(ev.marker == nil || ev.marker.DatabaseID != ev.record.DatabaseID):
		// A crash between the rename and the marker (section 5.2 step 10).
		if err := writeMarker(l, Marker{DatabaseID: ev.record.DatabaseID, MigratedAt: ev.record.CompletedAt}); err != nil {
			st.Warnings = append(st.Warnings, Warning{Code: "marker_not_written", Message: err.Error()})
		}
	}
	return st, nil
}

// legacySecretStop tells a wrong SECRET_KEY apart from lost material in
// S9: when the legacy data does not decrypt with it either, the secret is
// wrong, and `--replace` is not the way out.
func legacySecretStop(ctx context.Context, dataDir, secret string) *StopError {
	src, err := Open(ctx, dataDir, secret)
	if err != nil {
		return nil
	}
	defer src.Close()
	check, err := src.CheckSecret(ctx)
	if err == nil {
		return nil
	}
	return &StopError{State: S9, Code: CodeSecretMismatch, Entity: check.Entity, UserID: check.UserID,
		Message: "SECRET_KEY matches neither the Go database nor the legacy data; start with the SECRET_KEY the Python " +
			"release used", Err: err}
}

// lockAndClean is section 5.2 step 1 and state S6: the Go lock, then the
// removal of staging directories an interrupted run left behind.
func lockAndClean(o Options) (layout, *goLock, []Warning, error) {
	l, err := layoutOf(o.DataDir)
	if err != nil {
		return l, nil, nil, err
	}
	if err := l.ensureGoDir(); err != nil {
		return l, nil, nil, stop(S7, CodeGoDatabase, "the Go directory cannot be used", err)
	}
	lock, err := acquireLock(l.lock)
	if errors.Is(err, ErrLocked) {
		return l, nil, nil, stop("", CodeLocked, "another WebSSH process uses this data directory; stop it first", err)
	}
	if err != nil {
		return l, nil, nil, err
	}
	o.at(PointLocked)
	dirs, err := l.stagingDirs()
	var warnings []Warning
	for _, dir := range dirs {
		if err == nil {
			err = l.removeStaging(dir)
		}
	}
	if err != nil {
		return l, nil, nil, errors.Join(stop(S6, CodeActivation, "a staging directory of an interrupted migration cannot be removed", err), lock.release())
	}
	if len(dirs) > 0 {
		warnings = append(warnings, Warning{Code: "interrupted_migration_cleaned", Count: len(dirs),
			Message: "staging directories of an interrupted migration were removed"})
	}
	o.at(PointStagingClean)
	return l, lock, warnings, nil
}

// Exclusive runs fn with the Go lock held and the leftover staging
// directories removed, after Options.BeforeStart: the administrator
// commands that replace the Go database without a running server
// (`webssh backup restore`) use it. It refuses while another process
// holds the lock.
func Exclusive(ctx context.Context, o Options, fn func(ctx context.Context) error) error {
	if err := o.validate(); err != nil {
		return err
	}
	_, lock, _, err := lockAndClean(o)
	if err != nil {
		return err
	}
	if o.BeforeStart != nil {
		err = o.BeforeStart(ctx)
	}
	if err == nil {
		err = fn(ctx)
	}
	return errors.Join(err, lock.release())
}

// DryRun runs section 5.2 steps 2 to 9 into a staging directory and
// returns the report without activating anything (section 5.4). It uses
// throw-away keyring material and removes the staging directory; it never
// changes the legacy data or an active Go database. Go must not serve the
// data directory at the same time.
func DryRun(ctx context.Context, o Options) (*Report, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	// A dry run creates nothing in DATA_DIR: it takes the Go lock only
	// where the lock file exists, and leaves the staging directories of
	// an interrupted migration to the next start.
	l, err := layoutOf(o.DataDir)
	if err != nil {
		return nil, err
	}
	lock, err := acquireExistingLock(l.lock)
	if errors.Is(err, ErrLocked) {
		return nil, stop("", CodeLocked, "another WebSSH process uses this data directory; stop it first", err)
	}
	if err != nil {
		return nil, err
	}
	defer lock.release()
	if err := refuseDuringPurge(ctx, l); err != nil {
		return nil, err
	}
	if p, err := legacyPresence(l.dataDir); err != nil || p != legacyComplete {
		return nil, errors.Join(stop("", CodeReplaceNoLegacy, "there is no complete legacy source to migrate", nil), err)
	}
	r := &run{o: o, l: l, dryRun: true}
	if err := r.migrate(ctx); err != nil {
		return nil, err
	}
	return &r.report, r.discard()
}

// refuseDuringPurge refuses a dry run or a replacement while a purge is in
// progress (state S10): the legacy source is partly removed.
func refuseDuringPurge(ctx context.Context, l layout) error {
	present, err := l.databasePresent()
	if err != nil || !present {
		return nil
	}
	_, _, purge, err := inspectDatabase(ctx, l.database)
	if err != nil || purge == nil || !purge.InProgress {
		return nil
	}
	return purgeInProgress()
}

func purgeInProgress() *StopError {
	return stop(S10, CodePurgeInProgress, "`webssh legacy purge` was interrupted and the legacy data is "+
		"partly removed; start WebSSH or run `webssh legacy purge` again to complete it", nil)
}
