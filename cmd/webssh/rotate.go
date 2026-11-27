package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/bifrost0x/webssh/internal/admincli"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/buildinfo"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

func runRotateSecretKey(ctx context.Context, args []string, s streams) int {
	return rotateSecretKey(ctx, "webssh", args, s)
}

// rotateSecretKey is `rotate-secret-key --confirm-offline` (C-BAK-08).
func rotateSecretKey(ctx context.Context, prog string, args []string, s streams) int {
	return admincli.RotateSecretKey(ctx, prog, args, cliIO(s), openRotator)
}

func openRotator(context.Context) (admincli.SecretRotator, func() error, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	return &secretRotator{cfg: cfg}, func() error { return nil }, nil
}

// secretRotator runs the rotation on the stopped installation.
type secretRotator struct {
	cfg config.Config
	// checkpoint is passed to backup.RotateSecret (crash tests only).
	checkpoint func(string)
}

func (r *secretRotator) FromEnvironment() bool {
	return r.cfg.SecretSource == config.SecretFromEnvironment
}

// errRotationServing refuses the rotation beside a running server: it
// keeps the old keys in memory and would answer with them.
var errRotationServing = errors.New("WebSSH is running on this data directory; stop every WebSSH process, then repeat " +
	"the rotation. Nothing was changed")

// Rotate takes the Go lock (no server may run), refuses while legacy data
// exists (migration specification 4.9), writes and verifies a backup
// with the current secret and then rotates.
func (r *secretRotator) Rotate(ctx context.Context) (admincli.RotationReport, error) {
	o, err := migrationOptions(r.cfg, os.LookupEnv)
	if err != nil {
		return admincli.RotationReport{}, err
	}
	st, err := legacy.Start(ctx, o)
	if se, ok := errors.AsType[*legacy.StopError](err); ok {
		if se.Code == legacy.CodeLocked {
			return admincli.RotationReport{}, errRotationServing
		}
		return admincli.RotationReport{}, errors.New(se.Message)
	}
	if err != nil {
		return admincli.RotationReport{}, err
	}
	defer st.Close()
	if st.Migrated {
		return admincli.RotationReport{}, errors.New("legacy: unexpected migration")
	}
	if !legacyGone(r.cfg.DataDir, st.State) {
		return admincli.RotationReport{}, keyring.ErrRotationLegacy
	}
	secret, err := os.ReadFile(filepath.Join(r.cfg.DataDir, "secret_key")) // #nosec G304 -- DATA_DIR/secret_key
	if err != nil {
		return admincli.RotationReport{}, errors.New("persisted secret_key is required for rotation")
	}
	if string(trimSecret(secret)) != string(r.cfg.SecretKey.Bytes()) {
		return admincli.RotationReport{}, errors.New("persisted secret_key does not match the active old secret")
	}
	material, err := keyring.LoadOrCreateMaterial(r.cfg.DataDir, false)
	if err != nil {
		return admincli.RotationReport{}, err
	}
	ring, err := keyring.Open(r.cfg.SecretKey.Bytes(), material)
	if err != nil {
		return admincli.RotationReport{}, err
	}
	dbPath := filepath.Join(r.cfg.DataDir, keyring.GoDirName, keyring.DatabaseName)
	keyID, err := r.prepareDatabase(ctx, dbPath, ring)
	if err != nil {
		return admincli.RotationReport{}, err
	}
	path, err := r.writeBackup(ctx, dbPath, material, keyID)
	if err != nil {
		return admincli.RotationReport{}, err
	}
	db, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		return admincli.RotationReport{}, err
	}
	out, err := backup.RotateSecret(ctx, backup.RotateRequest{DataDir: r.cfg.DataDir, DB: db, Ring: ring, Material: material,
		LegacyPurged: true, Steps: rotationSteps(), WriteKeyID: legacy.WriteKeyIDTx, Checkpoint: r.checkpoint})
	err = errors.Join(err, db.Close())
	if err != nil {
		return admincli.RotationReport{}, err
	}
	rep := admincli.RotationReport{SSHKeys: out.Counts[stepSSHKeys], TOTPSecrets: out.Counts[stepTOTP],
		GitHubSecrets: out.Counts[stepGitHub], Credentials: out.Counts[stepCredentials], Backup: path}
	r.audit(rep)
	return rep, nil
}

// legacyGone reports that no legacy source exists: after the purge (S4),
// or for an installation that never had one. S5 (legacy data gone without
// a purge) still needs `webssh legacy purge` to record it.
func legacyGone(dataDir string, state legacy.State) bool {
	switch state {
	case legacy.S4:
		return true
	case legacy.S0, legacy.S2:
		_, err := os.Lstat(filepath.Join(dataDir, "app.db"))
		return errors.Is(err, fs.ErrNotExist)
	}
	return false
}

// trimSecret is the entrypoint's reading of the file: NUL bytes and
// trailing line feeds dropped.
func trimSecret(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != 0 {
			out = append(out, c)
		}
	}
	for len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out
}

// prepareDatabase opens the database with every schema of this build,
// binds or checks the key identifier, removes the pending secret of a
// rotation that never committed and closes the database cleanly for the
// backup.
func (r *secretRotator) prepareDatabase(ctx context.Context, dbPath string, ring *keyring.Ring) (string, error) {
	db, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		return "", err
	}
	err = db.ApplyAll(ctx, schemas()...)
	var stored string
	if err == nil {
		stored, err = legacy.StoredKeyID(ctx, db)
	}
	if err == nil && stored == "" {
		stored = ring.KeyID()
		err = legacy.RecordKeyID(ctx, db, stored)
	}
	if err == nil {
		err = ring.Verify(stored)
	}
	if err == nil {
		err = backup.DiscardStaleRotation(r.cfg.DataDir, ring, stored)
	}
	return stored, errors.Join(err, db.Close())
}

// writeBackup writes the pre-rotation backup with the current secret and
// verifies it, next to DATA_DIR or else in BACKUP_TEMP_DIR (as the Python
// release placed its recovery snapshot).
func (r *secretRotator) writeBackup(ctx context.Context, dbPath string, material []byte, keyID string) (string, error) {
	var errs []error
	for _, dir := range []string{filepath.Dir(r.cfg.DataDir), r.cfg.BackupTempDir} {
		if dir == "" {
			continue
		}
		path, err := backup.Write(dir, backup.Contents{Database: dbPath, SecretKey: r.cfg.SecretKey.Bytes(), Material: material,
			KeyID: keyID, Release: buildinfo.Read().Version, Reason: "pre-rotation", Now: time.Now()})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := backup.Verify(ctx, path, vault.ProbeSealed, totp.ProbeSealed); err != nil {
			// The archive holds SECRET_KEY; one that does not verify is
			// not left behind.
			return "", errors.Join(fmt.Errorf("the backup before the rotation does not verify: %w", err), os.Remove(path))
		}
		return path, nil
	}
	return "", fmt.Errorf("no directory for the backup before the rotation: %w", errors.Join(errs...))
}

// audit records the rotation. It runs after the commit; a log that cannot
// be opened does not undo or fail a completed rotation.
func (r *secretRotator) audit(rep admincli.RotationReport) {
	a, err := audit.Open(filepath.Join(r.cfg.DataDir, keyring.LogsDirName),
		audit.Options{MaxBytes: r.cfg.Audit.LogMaxBytes, BackupCount: r.cfg.Audit.BackupCount})
	if err != nil {
		return
	}
	a.Security("SECRET_ROTATION_SUCCESS", "rotated_keys", rep.SSHKeys, "rotated_named_records", rep.Credentials)
	_ = a.Close()
}

// completeRotation finishes a rotation that committed but did not install
// its secret (backup.CompleteRotation). Every command and the server run
// it right after the configuration is read, before any key check; when it
// installed the secret, the configuration is read again.
func completeRotation(ctx context.Context, cfg config.Config) (bool, error) {
	dbPath := filepath.Join(cfg.DataDir, keyring.GoDirName, keyring.DatabaseName)
	return backup.CompleteRotation(cfg.DataDir,
		func() ([]byte, error) { return keyring.LoadOrCreateMaterial(cfg.DataDir, false) },
		func() (string, error) {
			if _, err := os.Lstat(dbPath); err != nil {
				return "", fmt.Errorf("a secret rotation is pending, but the Go database cannot be found: %w", err)
			}
			db, err := store.Open(ctx, dbPath, store.Options{})
			if err != nil {
				return "", err
			}
			id, err := legacy.StoredKeyID(ctx, db)
			return id, errors.Join(err, db.Close())
		})
}
