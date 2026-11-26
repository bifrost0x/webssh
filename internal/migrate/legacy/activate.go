package legacy

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// activate is section 5.2 steps 10.2 to 11. Step 10.1, the record, was
// written with the last migration step. A crash before the rename leaves
// the previous state with a staging directory (S6, then S1 or S3); after
// the rename the database is complete and valid (S2). Failures after the
// rename do not undo it: the next start writes a missing marker and
// removes a leftover staging directory, so they are returned as warnings.
func (r *run) activate(ctx context.Context) (reportPath string, warnings []Warning, err error) {
	staged := filepath.Join(r.staging, stagedDBName)
	if err := r.db.CloseForActivation(ctx); err != nil {
		return "", nil, errors.Join(stop("", CodeActivation, "the staged database could not be closed for activation", err), r.discard())
	}
	r.db = nil
	r.o.at(PointClosed)
	if err := r.moveStaleSideFiles(); err != nil {
		return "", nil, errors.Join(stop("", CodeActivation, "stale side files of an earlier database could not be moved aside", err), r.discard())
	}
	r.o.at(PointSideFilesMove)
	if err := os.Rename(staged, r.l.database); err != nil {
		return "", nil, errors.Join(stop("", CodeActivation, "the staged database could not be moved into place", err), r.discard())
	}
	r.o.at(PointRenamed)
	note := func(code string, err error) {
		if err != nil {
			warnings = append(warnings, Warning{Code: code, Message: err.Error()})
		}
	}
	note("go_directory_not_synced", syncDir(r.l.goDir))
	r.o.at(PointDirSynced)
	note("marker_not_written", writeMarker(r.l, Marker{DatabaseID: r.dbID, MigratedAt: r.report.FinishedAt}))
	r.o.at(PointMarker)
	note("staging_not_removed", r.discard())
	r.o.at(PointStagingGone)
	reportPath, err = writeReportFile(r.l.goDir, r.report, r.o.now())
	note("report_not_written", err)
	r.o.at(PointReport)
	return reportPath, warnings, nil
}

// moveStaleSideFiles is step 10.4: -wal, -shm or -journal files at the
// target that belong to no open database are moved into replaced-<UTC>/,
// so that SQLite never applies them to the new database.
func (r *run) moveStaleSideFiles() error {
	var dir string
	for _, suffix := range sideFiles {
		side := r.l.database + suffix
		if _, err := os.Lstat(side); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if dir == "" {
			var err error
			if dir, err = r.l.replacedDir(r.o.now()); err != nil {
				return err
			}
		}
		if err := os.Rename(side, filepath.Join(dir, filepath.Base(side))); err != nil {
			return err
		}
	}
	if dir == "" {
		return nil
	}
	return syncDir(r.l.goDir)
}

// copyVerified copies src to dst (which must not exist) with mode 0600,
// fsyncs it and compares the SHA-256 of both files.
func copyVerified(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- the Go database
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a Go-owned path
	if err != nil {
		return err
	}
	h := sha256.New()
	_, cerr := io.Copy(io.MultiWriter(out, h), in)
	serr := out.Sync()
	if err := errors.Join(cerr, serr, out.Close()); err != nil {
		return errors.Join(err, os.Remove(dst))
	}
	back, err := fileSHA256(dst)
	if err != nil || back != string(h.Sum(nil)) {
		return errors.Join(fmt.Errorf("legacy: the copy of %s does not read back equal", src), err)
	}
	return syncDir(filepath.Dir(dst))
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- a Go-owned path
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return string(h.Sum(nil)), nil
}
