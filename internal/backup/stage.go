package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ErrIncompatible reports a Go archive whose database this build cannot
// open (a newer release wrote it).
var ErrIncompatible = fmt.Errorf("%w: backup data schema is newer than this WebSSH version", ErrInvalid)

// stagedPrefix names the staging directory of a restore in the Go
// directory, beside the database it replaces (same file system).
const stagedPrefix = ".restore-"

// stagedSecretName and previousSecretName are the archive's SECRET_KEY
// and the replaced DATA_DIR/secret_key in the staging directory.
const (
	stagedSecretName   = "secret_key"
	previousSecretName = "previous-secret_key"
)

// PointRestoreResealed is the checkpoint of Stage after a Go archive was
// resealed under the active ring, inside the staging transaction.
const PointRestoreResealed = "restore-resealed"

// stagedReportName is the migration report of a Python archive in the
// staging directory; the activation keeps it in the Go directory as
// restoreReportPrefix<UTC>.json (migration-spec 5.6).
const (
	stagedReportName    = "migration-report.json"
	restoreReportPrefix = "restore-report-"
)

// Installation is the live installation a restore goes into.
type Installation struct {
	DataDir string
	// SecretKey is the active SECRET_KEY (I-08); EnvironmentSecret says
	// it came from the environment.
	SecretKey         []byte
	EnvironmentSecret bool
	// AdoptSecret is true when SECRET_KEY comes from DATA_DIR/secret_key:
	// a Go archive made with another SECRET_KEY then brings its own, as
	// the Python release restored the archive's secret_key file. With
	// SECRET_KEY from the environment such an archive is refused, since
	// the environment would still win at the next start.
	AdoptSecret bool
	// KeepSecret is true while a legacy source exists: Go never writes
	// DATA_DIR/secret_key then (migration specification 4.9), so a Go
	// archive made with another SECRET_KEY is resealed under the active
	// ring with Reseal, the steps of rotate-secret-key, instead of
	// bringing its own key. The keyring material stays as well.
	KeepSecret bool
	Reseal     []RotationStep
	// Checkpoint is called at PointRestoreResealed; only the crash tests
	// set it.
	Checkpoint func(string)
	// MaterialPath and Material are the installation's keyring material
	// (keyring.MaterialLocation); Material is nil on a new installation.
	MaterialPath string
	Material     []byte
	// Schemas are every schema of this build; a restored database is
	// brought to them before it is activated.
	Schemas []store.Schema
	// Prepare adapts a staged database to the installation in one
	// transaction (the restore semantics of the Python release and
	// specification 5.6): remote credentials dropped and the recovery
	// check notice set for an export, every account's generation raised,
	// sessions and persistent terminal sessions dropped, and the
	// installation's own migration state and key id carried over.
	Prepare func(ctx context.Context, tx *store.Tx, p Prepared) error
	Probes  []Probe
	Limits  Limits
	// Legacy restores and inspects Python backups.
	Legacy interface {
		LegacyRestorer
		LegacyInspector
	}
	// Work is a private directory below BACKUP_TEMP_DIR for extraction.
	Work string
	Now  func() time.Time
}

func (in *Installation) now() time.Time {
	if in.Now != nil {
		return in.Now().UTC()
	}
	return time.Now().UTC()
}

func (in *Installation) goDir() string { return filepath.Join(in.DataDir, keyring.GoDirName) }

// Prepared tells Installation.Prepare what is restored.
type Prepared struct {
	Kind ArchiveKind
	// Export: remote credentials are dropped and the notice is set.
	Export     bool
	KeyID      string
	RestoredAt time.Time
}

// StageRequest names the archive to restore.
type StageRequest struct {
	OperationID string
	Archive     string
	// Portable restores the archive as an export whatever it holds (the
	// web restore never restores remote credentials, as in Python).
	Portable bool
	// RecoverySnapshot keeps the credentials of a Python archive
	// (`backup restore --recovery-snapshot`). Go archives keep them
	// unless they are exports.
	RecoverySnapshot bool
}

// Staged is a verified, prepared database waiting for activation.
type Staged struct {
	OperationID string
	Kind        ArchiveKind
	// Dir is the staging directory in the Go directory; it holds
	// webssh.db.
	Dir string
	// Material is the staged keyring material file, or "" when the
	// installation's material stays.
	Material string
	// Secret is true when the staging directory holds the archive's
	// SECRET_KEY (stagedSecretName), which replaces DATA_DIR/secret_key.
	Secret bool
	KeyID  string
	Export bool
	// Report is the migration report of a Python archive (JSON).
	Report string
}

// Stage verifies an archive and prepares the database it restores in a
// staging directory of the Go directory; the live database and material
// are not touched. A Go archive is read strictly (D-30) and must open
// with the active SECRET_KEY, or with its own under AdoptSecret, where it
// either brings that key or, under KeepSecret, is resealed under the
// active one; a Python archive goes through the migration
// (LegacyRestorer). On error nothing is left behind.
func Stage(ctx context.Context, in *Installation, req StageRequest) (st Staged, err error) {
	f, err := os.Open(req.Archive) // #nosec G304 G703 -- the archive the operator names or an operation's own file
	if err != nil {
		return st, fmt.Errorf("backup: open the archive: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return st, errors.Join(fmt.Errorf("%w: not a regular file", ErrInvalid), err)
	}
	family, err := detect(f, info.Size())
	if err != nil {
		return st, err
	}
	if !validOperationID(req.OperationID) {
		return st, errors.New("backup: invalid operation id")
	}
	st = Staged{OperationID: req.OperationID, Dir: filepath.Join(in.goDir(), stagedPrefix+req.OperationID)}
	if err := os.Mkdir(st.Dir, 0o700); err != nil {
		return Staged{}, fmt.Errorf("backup: create the staging directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, discardStaged(st))
			st = Staged{}
		}
	}()
	db := filepath.Join(st.Dir, keyring.DatabaseName)
	var material []byte
	var reason string
	var reseal *keyring.Rotation
	if family == familyGo {
		v, err := VerifyWith(ctx, req.Archive, VerifyOptions{Secret: in.SecretKey, AdoptSecret: in.AdoptSecret,
			Material: in.Material, Probes: in.Probes, Limits: in.Limits, Database: db, Work: in.Work})
		if errors.Is(err, ErrSecretMismatch) && in.EnvironmentSecret {
			return st, fmt.Errorf("%w; SECRET_KEY is set in the environment and would stay active: "+
				"set it to the archive's SECRET_KEY, or unset it to restore with the archive's key", err)
		}
		if err != nil {
			return st, err
		}
		st.Kind, st.KeyID, material, reason = KindGo, v.Ring.KeyID(), v.Material, v.Manifest.Reason
		st.Export = req.Portable || reason == ReasonExport
		if !bytes.Equal(v.Secret, in.SecretKey) {
			if err := checkSecret(v.Secret); err != nil {
				return st, fmt.Errorf("%w: %w", ErrInvalid, err)
			}
			if in.KeepSecret {
				if reseal, err = restoreRotation(in, v.Ring); err != nil {
					return st, err
				}
				st.KeyID, material = reseal.To().KeyID(), in.Material
			} else {
				st.Secret = true
				if err := writePrivate(filepath.Join(st.Dir, stagedSecretName), v.Secret); err != nil {
					return st, fmt.Errorf("backup: stage the SECRET_KEY: %w", err)
				}
			}
		}
	} else {
		if st, err = stageLegacy(ctx, in, req, f, info.Size(), st); err != nil {
			return st, err
		}
		material = in.Material
	}
	if err := prepareStaged(ctx, in, db, reseal, Prepared{Kind: st.Kind, Export: st.Export, KeyID: st.KeyID, RestoredAt: in.now()}); err != nil {
		return st, err
	}
	if !bytes.Equal(material, in.Material) {
		st.Material = stagedMaterialPath(in.MaterialPath, req.OperationID)
		if err := writePrivate(st.Material, material); err != nil {
			return st, fmt.Errorf("backup: stage the keyring material: %w", err)
		}
	}
	return st, nil
}

func stageLegacy(ctx context.Context, in *Installation, req StageRequest, f *os.File, size int64, st Staged) (Staged, error) {
	if in.Legacy == nil || in.Material == nil || in.Work == "" {
		return st, errors.New("backup: this installation cannot restore Python backups (no keyring yet; start WebSSH once)")
	}
	ring, err := keyring.Open(in.SecretKey, in.Material)
	if err != nil {
		return st, fmt.Errorf("backup: open the keyring: %w", err)
	}
	work, err := os.MkdirTemp(in.Work, "legacy-")
	if err != nil {
		return st, fmt.Errorf("backup: create the extraction directory: %w", err)
	}
	defer os.RemoveAll(work)
	keep := req.RecoverySnapshot && !req.Portable
	out, err := in.Legacy.RestoreLegacy(ctx, LegacyRestore{Archive: f, Size: size, Staging: work, Limits: in.Limits,
		SecretKey: in.SecretKey, EnvironmentSecret: in.EnvironmentSecret, Ring: ring, RecoverySnapshot: keep, RestoredAt: in.now()})
	if err != nil {
		return st, err
	}
	if err := moveFile(out.Database, filepath.Join(st.Dir, keyring.DatabaseName)); err != nil {
		return st, fmt.Errorf("backup: stage the migrated database: %w", err)
	}
	if err := writePrivate(filepath.Join(st.Dir, stagedReportName), []byte(out.Report)); err != nil {
		return st, fmt.Errorf("backup: stage the migration report: %w", err)
	}
	st.Kind, st.KeyID, st.Export, st.Report = out.Kind, ring.KeyID(), !keep, out.Report
	return st, nil
}

// restoreRotation is the reseal of a Go archive's records from its ring
// to the installation's ring (KeepSecret).
func restoreRotation(in *Installation, archive *keyring.Ring) (*keyring.Rotation, error) {
	if len(in.Reseal) == 0 || in.Material == nil {
		return nil, errors.New("backup: this installation cannot reseal a Go archive made with another SECRET_KEY")
	}
	active, err := keyring.Open(in.SecretKey, in.Material)
	if err != nil {
		return nil, fmt.Errorf("backup: open the keyring: %w", err)
	}
	return keyring.NewRestoreRotation(archive, active)
}

// prepareStaged brings the staged database to this build's schemas,
// applies the restore semantics, reseals it under the active ring when
// reseal is set, and closes it for activation. Restore semantics and
// reseal are one transaction.
func prepareStaged(ctx context.Context, in *Installation, path string, reseal *keyring.Rotation, p Prepared) error {
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		return fmt.Errorf("%w: database: %w", ErrInvalid, err)
	}
	if err := db.ApplyAll(ctx, in.Schemas...); err != nil {
		return errors.Join(fmt.Errorf("%w: %w", ErrIncompatible, err), db.Close())
	}
	if in.Prepare != nil || reseal != nil {
		err := db.Write(ctx, func(tx *store.Tx) error {
			if in.Prepare != nil {
				if err := in.Prepare(ctx, tx, p); err != nil {
					return err
				}
			}
			if reseal == nil {
				return nil
			}
			if _, err := resealTx(ctx, tx, reseal, in.Reseal); err != nil {
				return fmt.Errorf("reseal under the active SECRET_KEY: %w", err)
			}
			if in.Checkpoint != nil {
				in.Checkpoint(PointRestoreResealed)
			}
			return nil
		})
		if err != nil {
			return errors.Join(fmt.Errorf("backup: prepare the restored database: %w", err), db.Close())
		}
	}
	if p.Export {
		if err := db.Vacuum(ctx); err != nil {
			return errors.Join(err, db.Close())
		}
	}
	if err := db.IntegrityCheck(ctx); err != nil {
		return errors.Join(fmt.Errorf("%w: database: %w", ErrInvalid, err), db.Close())
	}
	return db.CloseForActivation(ctx)
}

func stagedMaterialPath(materialPath, operationID string) string {
	return filepath.Join(filepath.Dir(materialPath), stagedPrefix+"material-"+operationID)
}

func previousMaterialPath(materialPath, operationID string) string {
	return filepath.Join(filepath.Dir(materialPath), stagedPrefix+"previous-material-"+operationID)
}

// discardStaged removes a staging directory and staged material.
func discardStaged(st Staged) error {
	var errs []error
	if st.Material != "" {
		errs = append(errs, removeIfPresent(st.Material))
	}
	if st.Dir != "" {
		errs = append(errs, os.RemoveAll(st.Dir))
	}
	return errors.Join(errs...)
}

// writePrivate writes a new file with mode 0600 and syncs it and its
// directory.
func writePrivate(path string, data []byte) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a Go-owned staging path
	if err != nil {
		return err
	}
	_, err = out.Write(data)
	if err = errors.Join(err, out.Sync(), out.Close()); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return syncDir(filepath.Dir(path))
}

func removeIfPresent(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// validOperationID accepts the URL-safe identifiers operations use.
func validOperationID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
