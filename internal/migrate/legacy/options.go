package legacy

import (
	"errors"
	"time"
)

// Options configure Start, DryRun and Replace.
type Options struct {
	// DataDir is the resolved DATA_DIR.
	DataDir string
	// Secret is SECRET_KEY, resolved as entrypoint.sh does (I-08), and
	// SecretSource where it came from ("file" or "environment").
	Secret       string
	SecretSource string
	// BackupTempDir is BACKUP_TEMP_DIR, where the Python release keeps its
	// backup operation lock and restore status. Empty skips those checks
	// with a warning in the report.
	BackupTempDir string
	// Release is the Go release for the record and the report.
	Release string
	// Registry holds the migration steps of this build.
	Registry *Registry
	// Origin is the evaluated legacy origin rule (K6 A1, D-01): whether the
	// Python configuration compared only host and port for realtime
	// connections. The composition root evaluates it with
	// realtime.KeepLegacySchemeRule for the configuration at hand; the
	// migration records it as the setting SettingIgnoreOriginScheme.
	Origin OriginRule
	// Now returns the current time; nil means time.Now.
	Now func() time.Time

	// checkpoint is called at every state transition of a run; tests use
	// it to inject crashes. Nil in production.
	checkpoint func(point string)
	// freeSpace replaces the free space query in tests.
	freeSpace func(dir string) (uint64, error)
}

// OriginRule is the evaluated K6 A1 rule with the configuration it was
// evaluated on, for the report.
type OriginRule struct {
	KeepLegacyScheme bool
	Evidence         string
}

// SettingIgnoreOriginScheme is the derived setting that makes the
// realtime origin check compare host and port only, as the Python release
// did (OriginPolicy.IgnoreScheme). Its value is "true" when stored.
const SettingIgnoreOriginScheme = "realtime.origin.ignore_scheme"

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o Options) at(point string) {
	if o.checkpoint != nil {
		o.checkpoint(point)
	}
}

func (o Options) validate() error {
	switch {
	case o.DataDir == "":
		return errors.New("legacy: no data directory")
	case o.Secret == "":
		return errors.New("legacy: SECRET_KEY is empty")
	case o.Registry == nil:
		return errors.New("legacy: no migration registry")
	}
	return nil
}

// Checkpoints of a run, in order. Each names the state reached; a crash
// right after it must leave a state the next start resolves (section 5.2
// step 10 and section 8.3).
const (
	PointLocked        = "locked"
	PointStagingClean  = "staging-cleaned"
	PointRead          = "legacy-read"
	PointMaterial      = "material-ready"
	PointStaged        = "staging-created"
	PointWritten       = "steps-written"
	PointCommitted     = "record-committed"
	PointClosed        = "staging-closed"
	PointSideFilesMove = "side-files-moved"
	PointRenamed       = "database-renamed"
	PointDirSynced     = "go-directory-synced"
	PointMarker        = "marker-written"
	PointStagingGone   = "staging-removed"
	PointReport        = "report-written"
	PointReplacedSaved = "replaced-database-saved"
)
