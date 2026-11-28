package legacy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// spaceMargin is added to the space the migration needs (section 5.2
// step 5).
const spaceMargin = 64 << 20

// dryRunPrefix names the scratch directory of a dry run in TMPDIR.
const dryRunPrefix = "webssh-migrate-dry-run-"

// run is one migration of the legacy source into a staging database:
// section 5.2 steps 2 to 9. Activation is a separate step (activate.go).
type run struct {
	o        Options
	l        layout
	dryRun   bool
	report   Report
	listing  Listing
	src      *Source
	segments []segment
	accounts []AccountRow // every account, for the account steps
	pending  []Pending
	ring     *keyring.Ring
	staging  string
	db       *store.DB
	dbID     string
	replaced string // path of the database this run replaces, for the record
	// extraSpace is what --replace needs beside the migration: the copy
	// of the database it keeps.
	extraSpace int64
	// openOpts open the source (a restore opens an extracted archive
	// with PrivateCopy and Restored); presetRing is the keyring a restore
	// seals with instead of the material of the source directory.
	openOpts   []Option
	presetRing *keyring.Ring
}

// migrate runs steps 2 to 9. On error it has released everything and
// removed the staging directory; the legacy data and an active Go
// database are unchanged.
func (r *run) migrate(ctx context.Context) error {
	if err := r.preflight(ctx); err != nil {
		return err
	}
	return r.build(ctx)
}

// preflight is every check of steps 2 to 5 and the reading of the legacy
// data, before anything is written: a running Python, the source digest
// and its links, the space, SECRET_KEY and every step's Read. --replace
// runs it before it sets the old database aside. On error it has released
// the source.
func (r *run) preflight(ctx context.Context) error {
	r.report = newReport(r.o.Release, r.o.now(), r.l.dataDir)
	r.report.Source.SecretKeySource = r.o.SecretSource
	if err := r.checkBeforeWriting(ctx); err != nil {
		return errors.Join(err, r.discard())
	}
	return nil
}

// build is steps 7 to 9 after a successful preflight.
func (r *run) build(ctx context.Context) error {
	if err := r.buildStaging(ctx); err != nil {
		return errors.Join(err, r.discard())
	}
	return nil
}

func (r *run) checkBeforeWriting(ctx context.Context) error {
	warnings, err := pythonIdle(r.l.dataDir, r.o.BackupTempDir)
	if err != nil {
		return err
	}
	r.report.Warnings = append(r.report.Warnings, warnings...)
	if r.listing, err = scanSource(r.l.dataDir, nil, 0); err == nil {
		err = strictListing(r.listing)
	}
	if err != nil {
		return sourceStop(err)
	}
	r.report.Source.Digest, r.report.Source.Files = r.listing.Digest(), len(r.listing.Files)
	if err := r.checkSpace(); err != nil {
		return err
	}
	if err := r.read(ctx); err != nil {
		return err
	}
	r.o.at(PointRead)
	return nil
}

func (r *run) buildStaging(ctx context.Context) error {
	if err := r.prepareKeyring(); err != nil {
		return err
	}
	r.o.at(PointMaterial)
	if err := r.stage(ctx); err != nil {
		return err
	}
	r.o.at(PointStaged)
	if err := r.write(ctx); err != nil {
		return err
	}
	r.o.at(PointCommitted)
	if err := errors.Join(r.db.IntegrityCheck(ctx), foreignKeyCheck(ctx, r.db)); err != nil {
		return stop("", CodeVerifyFailed, "the staged database failed its integrity check", err)
	}
	return nil
}

// checkSpace is step 5: three times app.db plus the per-user stores plus
// a margin must be free on the file system of the Go directory.
func (r *run) checkSpace() error {
	need := uint64(3*r.listing.size("app.db")+r.listing.bytesBelow("users")+r.extraSpace) + spaceMargin // #nosec G115 -- sizes are not negative
	dir := r.l.goDir
	if _, err := os.Lstat(dir); err != nil {
		dir = r.l.dataDir
	}
	if r.dryRun {
		dir = os.TempDir()
	}
	query := freeBytes
	if r.o.freeSpace != nil {
		query = r.o.freeSpace
	}
	free, err := query(dir)
	if err != nil {
		return stop("", CodeNoSpace, "the free space of the data directory could not be determined", err)
	}
	if free < need {
		return stop("", CodeNoSpace, fmt.Sprintf("the migration needs %d bytes on the file system of %s, %d are free; "+
			"free space and start again", need, dir, free), nil)
	}
	return nil
}

// read opens the legacy source, checks SECRET_KEY and runs every step's
// Read. Nothing is written before it succeeds.
func (r *run) read(ctx context.Context) error {
	src, err := Open(ctx, r.l.dataDir, r.o.Secret, r.openOpts...)
	switch {
	case errors.Is(err, fs.ErrPermission):
		return sourceStop(err)
	case errors.Is(err, ErrJournal):
		return stop("", CodeLegacyInUse, "app.db has an unfinished transaction; start and stop the Python release once so "+
			"that it recovers its own transaction, then start again", err)
	case errors.Is(err, ErrUnsafePath):
		return stop("", CodeUnsafeSource, "the legacy source contains a symbolic link or a special file", err)
	case err != nil:
		return stop(S7, CodeLegacyUnknown, "the legacy data is not a supported Python release's data", err)
	}
	r.src = src
	if err := src.CheckIntegrity(ctx); err != nil {
		return stop(S7, CodeLegacyUnknown, "app.db is damaged or not a WebSSH database", err)
	}
	r.report.Source.SchemaShape = shapeOf(src.Schema())
	if r.report.Source.Tables, err = src.Tables(ctx); err != nil {
		return stop(S7, CodeLegacyUnknown, "app.db cannot be read", err)
	}
	check, err := src.CheckSecret(ctx)
	if err != nil {
		return &StopError{Code: CodeSecretMismatch, Entity: check.Entity, UserID: check.UserID,
			Message: "SECRET_KEY does not match the stored data; start with the SECRET_KEY the Python release used", Err: err}
	}
	r.report.Source.SecretChecked = check.Checked
	if !check.Checked {
		r.report.Warnings = append(r.report.Warnings, Warning{Code: "secret_key_not_checked",
			Message: "the legacy data holds no encrypted record, so SECRET_KEY could not be checked"})
	}
	if r.segments, err = r.o.Registry.segments(r.o.wholeSource); err != nil {
		return stop("", CodeStepFailed, "the migration steps are inconsistent", err)
	}
	if r.accounts, err = src.AccountRows(ctx); err != nil {
		return stop(S7, CodeLegacyUnknown, "app.db cannot be read", err)
	}
	for i := range r.segments {
		seg := &r.segments[i]
		if seg.step == nil {
			if err := r.readAccounts(ctx, seg); err != nil {
				return err
			}
			continue
		}
		if err := seg.step.Read(ctx, src); err != nil {
			return stepStop(seg.step.Entity(), "the legacy data could not be read", err)
		}
	}
	if r.pending, err = r.o.Registry.countPending(ctx, src); err != nil {
		return err
	}
	return nil
}

// prepareKeyring is the first part of step 7. A dry run uses throw-away
// material and writes none.
func (r *run) prepareKeyring() error {
	if r.presetRing != nil {
		r.ring = r.presetRing
		return nil
	}
	var material []byte
	if r.dryRun {
		material = make([]byte, keyring.MaterialSize)
		_, _ = rand.Read(material) // crypto/rand.Read never fails
	} else {
		// Side files of a database that is gone would make the keyring
		// refuse new material; they are moved aside first (step 10.4).
		if present, err := r.l.databasePresent(); err != nil || !present {
			if err := errors.Join(err, r.moveStaleSideFiles()); err != nil {
				return stop("", CodeActivation, "stale side files of an earlier database could not be moved aside", err)
			}
		}
		var err error
		if material, err = keyring.LoadOrCreateMaterial(r.l.dataDir, true); err != nil {
			return stop(S9, CodeKeyMaterial, "the keyring material cannot be created or read", err)
		}
	}
	ring, err := keyring.Open([]byte(r.o.Secret), material)
	if err != nil {
		return stop("", CodeKeyMaterial, "the keyring cannot be opened", err)
	}
	if !r.dryRun {
		if _, err := keyring.MoveMaterialToState(r.l.dataDir, ring, ""); err != nil {
			return stop(S9, CodeKeyMaterial, "the keyring material in go/ could not be moved to logs/.webssh-go/", err)
		}
	}
	r.ring = ring
	return nil
}

// stage creates the staging directory and database with every schema.
func (r *run) stage(ctx context.Context) error {
	var err error
	if r.dryRun {
		// The scratch database of a dry run lives outside DATA_DIR.
		r.staging, err = os.MkdirTemp("", dryRunPrefix)
	} else {
		r.staging, err = r.l.newStaging()
	}
	if err != nil {
		return stop("", CodeActivation, "the staging directory cannot be created", err)
	}
	if r.db, err = store.Open(ctx, filepath.Join(r.staging, stagedDBName), store.Options{}); err != nil {
		return stop("", CodeActivation, "the staging database cannot be created", err)
	}
	schemas := append([]store.Schema{RecordSchema(), settings.Schema()}, r.o.Registry.schemas...)
	if err := r.db.ApplyAll(ctx, schemas...); err != nil {
		return stop("", CodeActivation, "the staging database schema cannot be created", err)
	}
	return nil
}

// recheckAndRecord is step 9 and step 10.1.
func (r *run) recheckAndRecord(ctx context.Context, tx *store.Tx) error {
	after, err := scanSource(r.l.dataDir, nil, 0)
	if err == nil {
		err = strictListing(after)
	}
	if err != nil || after.Digest() != r.listing.Digest() {
		return stop("", CodeChangedDuring, "the legacy data changed during the migration; stop the Python release and start again", err)
	}
	r.report.LegacyUntouched = Untouched{DigestBefore: r.listing.Digest(), DigestAfter: after.Digest(), Equal: true}
	r.listing = after
	r.report.Coverage = r.o.Registry.coverage()
	r.report.Pending = r.pending
	r.report.ReplacedDatabase = r.replaced
	r.report.Result = ResultCompleted
	if r.dryRun {
		r.report.Result = ResultDryRun
	}
	r.report.FinishedAt = utcText(r.o.now())
	return writeRecord(ctx, tx, Record{
		DatabaseID: r.dbID, GoRelease: r.o.Release, StartedAt: r.report.StartedAt, CompletedAt: r.report.FinishedAt,
		SourceDigest: after.Digest(), Listing: after.Files, ScannedAt: after.ScannedAt, SchemaShape: r.report.Source.SchemaShape,
		Coverage: r.report.Coverage, Pending: r.pending, Report: r.report, ReplacedDatabase: r.replaced,
	})
}

// discard releases the run and removes its staging directory.
func (r *run) discard() error {
	var errs []error
	if r.src != nil {
		errs = append(errs, r.src.Close())
		r.src = nil
	}
	if r.db != nil {
		errs = append(errs, r.db.Close())
		r.db = nil
	}
	switch {
	case r.staging == "":
	case r.dryRun:
		errs = append(errs, os.RemoveAll(r.staging))
	default:
		errs = append(errs, r.l.removeStaging(r.staging))
	}
	r.staging = ""
	return errors.Join(errs...)
}

// writeFailure writes the report of a failed run into the Go directory,
// so that the cause can be read after the process exited. A failure to
// write it is ignored: the error itself is returned to the caller.
func (r *run) writeFailure(err error) {
	se, ok := errors.AsType[*StopError](err)
	if !ok {
		se = &StopError{Code: CodeStepFailed, Message: err.Error()}
	}
	r.report.fail(se)
	r.report.FinishedAt = utcText(r.o.now())
	_, _ = writeReportFile(r.l.goDir, r.report, r.o.now())
}

// sourceStop names why the legacy source cannot be read. A permission
// error is reported as such: the usual cause is a data directory owned by
// another user than the one Go runs as (for example 99:100 on Unraid).
func sourceStop(err error) *StopError {
	if errors.Is(err, fs.ErrPermission) {
		return stop("", CodeUnreadable, fmt.Sprintf("a legacy file cannot be read by the user Go runs as (uid %d); "+
			"the data directory and its files must belong to that user, for example 99:100 on Unraid; correct the owner "+
			"and start again", os.Getuid()), err)
	}
	return stop("", CodeUnsafeSource, "the legacy source contains a symbolic link or a special file, or cannot be read", err)
}

func stepStop(entity, message string, err error) *StopError {
	s := &StopError{Code: CodeStepFailed, Entity: entity, Message: message, Err: err}
	if se, ok := errors.AsType[*StepError](err); ok {
		s.UserID, s.Record = se.UserID, se.Record
	}
	switch {
	case errors.Is(err, ErrUnsafePath):
		s.Code = CodeUnsafeSource
	case errors.Is(err, ErrRecordDamaged):
		// SECRET_KEY decrypted other records (CheckSecret): this one was
		// changed (migration specification 8.3).
		s.Code, s.Message = CodeRecordDamaged, "a stored secret does not decrypt with the SECRET_KEY that decrypts the other records; "+
			"it is damaged or was changed outside WebSSH. Restore the legacy data from a backup or remove the record in the Python release"
	}
	return s
}

func foreignKeyCheck(ctx context.Context, db *store.DB) error {
	return db.Read(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
		if err != nil {
			return fmt.Errorf("legacy: foreign_key_check: %w", err)
		}
		defer rows.Close()
		if rows.Next() {
			return errors.New("legacy: the staged database violates a foreign key")
		}
		return rows.Err()
	})
}
