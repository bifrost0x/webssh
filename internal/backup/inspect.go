package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bifrost0x/webssh/internal/store"
)

// Compatibility reasons, the texts of evaluate_backup_compatibility that
// the administration translates.
const (
	ReasonCurrent    = "backup data schema is current"
	ReasonLegacy     = "legacy archive can be migrated"
	ReasonMigratable = "backup data schema can be migrated"
	ReasonNewer      = "backup data schema is newer than this WebSSH version"
)

// Inspect verifies an archive as a restore would read it and summarises
// it (the upload check, `webssh backup verify`): a Go archive strictly,
// opened with the active SECRET_KEY, with its database brought to this
// build's schemas on a copy; a Python archive through LegacyInspector.
func Inspect(ctx context.Context, in *Installation, archive string) (Summary, error) {
	f, err := os.Open(archive) // #nosec G304 G703 -- the archive the operator names or an operation's own file
	if err != nil {
		return Summary{}, fmt.Errorf("backup: open the archive: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Summary{}, errors.Join(fmt.Errorf("%w: not a regular file", ErrInvalid), err)
	}
	family, err := detect(f, info.Size())
	if err != nil {
		return Summary{}, err
	}
	if family == familyPython {
		if in.Legacy == nil {
			return Summary{}, fmt.Errorf("%w: Python backups cannot be read here", ErrInvalid)
		}
		return in.Legacy.InspectLegacy(ctx, f, info.Size(), in.Limits)
	}
	work := in.Work
	if work == "" {
		work = filepath.Dir(archive)
	}
	tmp, err := os.MkdirTemp(work, ".webssh-backup-inspect-")
	if err != nil {
		return Summary{}, fmt.Errorf("backup: inspect: %w", err)
	}
	defer os.RemoveAll(tmp)
	db := filepath.Join(tmp, "webssh.db")
	v, err := VerifyWith(ctx, archive, VerifyOptions{Secret: in.SecretKey, AdoptSecret: in.AdoptSecret, Material: in.Material, Probes: in.Probes,
		Limits: in.Limits, Database: db})
	if err != nil {
		return Summary{}, err
	}
	s := Summary{Kind: KindGo, FormatVersion: v.Manifest.Version, DataSchemaVersion: v.Manifest.Version,
		CurrentDataSchemaVersion: FormatVersion, CreatedAt: v.Manifest.CreatedAt, FileCount: len(v.Manifest.Files),
		IncludesSecretKey: v.Manifest.IncludesSecretKey, IncludesRemoteCredentials: v.Manifest.Reason != ReasonExport,
		Compatible: true, CompatibilityReason: ReasonCurrent}
	for _, f := range v.Manifest.Files {
		s.TotalUncompressedSize += f.Size
	}
	if err := applySchemas(ctx, db, in.Schemas); err != nil {
		s.Compatible, s.CompatibilityReason = false, ReasonNewer
	}
	return s, nil
}

func applySchemas(ctx context.Context, path string, schemas []store.Schema) error {
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		return err
	}
	return errors.Join(db.ApplyAll(ctx, schemas...), db.Close())
}
