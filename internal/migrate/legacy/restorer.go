package legacy

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bifrost0x/webssh/internal/backup"
)

// Restorer restores Python backups (format 1 and 2) through the steps of
// the one-time migration (migration specification, section 5.6) and
// inspects them for the upload check. It implements
// backup.LegacyRestorer and backup.LegacyInspector.
type Restorer struct {
	// Options carry the registry, release, origin rule and clock of the
	// migration; DataDir, Secret and BackupTempDir are ignored.
	Options Options
	// Work is a private directory (below BACKUP_TEMP_DIR) for inspection.
	Work string
}

var (
	_ backup.LegacyRestorer  = (*Restorer)(nil)
	_ backup.LegacyInspector = (*Restorer)(nil)
)

func backupLimits(l backup.Limits) BackupLimits {
	if l == (backup.Limits{}) {
		l = backup.DefaultLimits
	}
	return BackupLimits{Members: l.MaxMembers, FileSize: uint64(max(l.MaxFileSize, 0)), // #nosec G115 -- not negative
		TotalSize: uint64(max(l.MaxTotalSize, 0)), Compression: uint64(max(l.MaxCompressionRatio, 0)), // #nosec G115 -- not negative
		ManifestBytes: uint64(max(l.MaxManifestSize, 0))} // #nosec G115 -- not negative
}

func invalid(err error) error { return fmt.Errorf("%w: %w", backup.ErrInvalid, err) }

func archiveKind(m BackupManifest) backup.ArchiveKind {
	if m.FormatVersion == 1 {
		return backup.KindPythonV1
	}
	return backup.KindPythonV2
}

// RestoreLegacy verifies the archive with the reading rules of the
// Python release, extracts what Python's restore would restore into
// req.Staging, applies Python's restore semantics and migrates the result
// into a new Go database sealed with req.Ring. Members under data/go/ are
// never written or opened. A SECRET_KEY that does not decrypt the
// archive's records stops the restore before anything is activated.
func (rs *Restorer) RestoreLegacy(ctx context.Context, req backup.LegacyRestore) (backup.LegacyOutcome, error) {
	var out backup.LegacyOutcome
	if req.Ring == nil || req.Staging == "" {
		return out, errors.New("legacy: a restore needs the active keyring and a staging directory")
	}
	limits := backupLimits(req.Limits)
	b, err := OpenBackupReader(req.Archive, req.Size, limits)
	if err != nil {
		return out, invalid(err)
	}
	mode := RestoreExport
	if req.RecoverySnapshot {
		mode = RestoreRecoverySnapshot
	}
	dataDir := filepath.Join(req.Staging, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		return out, fmt.Errorf("legacy: create the extraction directory: %w", err)
	}
	if _, err := ExtractBackup(b, dataDir, limits, mode); err != nil {
		return out, invalid(err)
	}
	secret, err := restoreSecret(dataDir, req)
	if err != nil {
		return out, err
	}
	o := rs.Options
	o.DataDir, o.Secret, o.SecretSource, o.BackupTempDir = dataDir, secret, "archive", ""
	if err := o.validate(); err != nil {
		return out, err
	}
	l, err := layoutOf(dataDir)
	if err != nil {
		return out, err
	}
	r := &run{o: o, l: l, openOpts: []Option{PrivateCopy(), Restored(mode, req.RestoredAt)}, presetRing: req.Ring}
	if err := r.migrate(ctx); err != nil {
		return out, err
	}
	if err := refuseActiveObjects(r.src.Schema()); err != nil {
		return out, errors.Join(invalid(err), r.discard())
	}
	// A migration keeps pending entities in the legacy data for a later
	// release. A restore has no legacy data that stays: the extraction is
	// removed, so whatever this build does not migrate would be lost.
	if names := pendingWithRecords(r.pending); len(names) > 0 {
		return out, errors.Join(stop("", CodeRestoreIncomplete, "this release does not migrate every entity of the archive, "+
			"so the restore would lose "+strings.Join(names, ", ")+"; restore it with the release that migrates them", nil), r.discard())
	}
	db := filepath.Join(r.staging, stagedDBName)
	err = errors.Join(r.src.Close(), r.db.CloseForActivation(ctx))
	r.src, r.db = nil, nil
	if err != nil {
		return out, err
	}
	report, err := json.Marshal(r.report)
	if err != nil {
		return out, err
	}
	return backup.LegacyOutcome{Database: db, Report: string(report), Kind: archiveKind(b.Manifest)}, nil
}

// restoreSecret is the key that decrypts the archive's legacy records
// (specification 5.6 step 4): SECRET_KEY from the environment wins, as
// it wins at Python's next start; otherwise the archive's
// data/secret_key, read as the entrypoint reads it; otherwise the active
// key.
func restoreSecret(dataDir string, req backup.LegacyRestore) (string, error) {
	if req.EnvironmentSecret {
		return string(req.SecretKey), nil
	}
	raw, err := readLimitedFile(filepath.Join(dataDir, "secret_key"), 64<<10)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return string(req.SecretKey), nil
	case err != nil:
		return "", invalid(err)
	}
	key := bytes.TrimRight(bytes.ReplaceAll(raw, []byte{0}, nil), "\n")
	if len(key) == 0 {
		return string(req.SecretKey), nil
	}
	return string(key), nil
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrUnsafePath, filepath.Base(path))
	}
	f, err := os.Open(path) // #nosec G304 -- a file this restore extracted
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(raw)) > limit {
		err = errors.New("legacy: data/secret_key is too large")
	}
	return raw, err
}

// refuseActiveObjects is the backup rule of inventory 4.6: an archived
// app.db with triggers or views was not written by WebSSH.
func refuseActiveObjects(s Schema) error {
	if len(s.Triggers) > 0 || len(s.Views) > 0 {
		return errors.New("legacy: the archived app.db contains triggers or views")
	}
	return nil
}

// InspectLegacy verifies a Python backup without restoring it: the
// reading rules of the restore and the archived database (quick_check,
// the users table, no triggers or views). It returns the summary the
// administration shows.
func (rs *Restorer) InspectLegacy(ctx context.Context, archive io.ReaderAt, size int64, l backup.Limits) (backup.Summary, error) {
	limits := backupLimits(l)
	b, err := OpenBackupReader(archive, size, limits)
	if err != nil {
		return backup.Summary{}, invalid(err)
	}
	work, err := os.MkdirTemp(rs.Work, "inspect-")
	if err != nil {
		return backup.Summary{}, fmt.Errorf("legacy: inspect: %w", err)
	}
	defer os.RemoveAll(work)
	if _, err := ExtractBackup(b, work, limits, RestoreRecoverySnapshot); err != nil {
		return backup.Summary{}, invalid(err)
	}
	src, err := Open(ctx, work, "inspection", PrivateCopy())
	if err != nil {
		return backup.Summary{}, invalid(err)
	}
	defer src.Close()
	if err := errors.Join(src.CheckIntegrity(ctx), refuseActiveObjects(src.Schema())); err != nil {
		return backup.Summary{}, invalid(err)
	}
	m := b.Manifest
	s := backup.Summary{Kind: archiveKind(m), FormatVersion: m.FormatVersion, DataSchemaVersion: m.DataSchemaVersion,
		CurrentDataSchemaVersion: currentSchemaFormat, CreatedAt: m.CreatedAt, Legacy: m.FormatVersion == 1,
		FileCount: len(m.Files), Compatible: true, CompatibilityReason: backup.ReasonCurrent}
	for _, f := range m.Files {
		s.TotalUncompressedSize += int64(min(f.Size, 1<<62)) // #nosec G115 -- bounded above
		s.IncludesRemoteCredentials = s.IncludesRemoteCredentials || remoteCredentialPath(f.Path)
		s.IncludesSecretKey = s.IncludesSecretKey || f.Path == "secret_key"
	}
	switch {
	case s.Legacy:
		s.CompatibilityReason = backup.ReasonLegacy
	case m.DataSchemaVersion < currentSchemaFormat:
		s.CompatibilityReason = backup.ReasonMigratable
	}
	return s, nil
}
