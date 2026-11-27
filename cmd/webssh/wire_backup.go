package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/buildinfo"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
	"github.com/bifrost0x/webssh/internal/vault"
)

// backupArea wires the area "backup" (OP1): backup and restore (internal/backup, restore of Python backups through internal/migrate/legacy).
// OP1 fills in the hooks; no other package edits this file.
func backupArea() extension {
	return extension{name: "backup", migrate: migrateBackup, prepare: prepareBackup, wire: wireBackup}
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ backup.StepUp      = (*stepup.Service)(nil)
	_ backup.Snapshotter = (*store.DB)(nil)
	_ backup.Maintenance = (*maintenance)(nil)
	_ backup.Auditor     = backupAudit{}
	_ interface {
		backup.LegacyRestorer
		backup.LegacyInspector
	} = (*legacy.Restorer)(nil)
)

// migrateBackup registers the steps of E39 and A10.
func migrateBackup(r *legacy.Registry, cfg config.Config, _ config.LookupFunc) error {
	return legacy.AddBackupState(r, cfg.BackupTempDir)
}

// prepareBackup keeps the server in maintenance while a restore is
// unfinished or its rollback failed.
func prepareBackup(sys *system) error {
	if blocked, msg := restoreBlocked(sys.cfg.DataDir); blocked {
		if _, err := sys.maintenance.Enter(context.Background(), backup.MaintenanceRestore); err != nil {
			return err
		}
		sys.log.Error("restore maintenance: the last restore is not finished; run `webssh backup restore`", "message", msg)
	}
	return nil
}

// backupNamespace is the Go directory below BACKUP_TEMP_DIR of this
// installation: beside the namespace of the Python release
// (instance-<hash>), never inside DATA_DIR.
func backupNamespace(cfg config.Config) (string, error) {
	root := cfg.BackupTempDir
	if root == "" {
		root = filepath.Join(os.TempDir(), "webssh-backup-operations")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	data, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return "", err
	}
	if root == data || strings.HasPrefix(root, data+string(filepath.Separator)) || strings.HasPrefix(data, root+string(filepath.Separator)) {
		return "", errors.New("BACKUP_TEMP_DIR must be outside DATA_DIR")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("BACKUP_TEMP_DIR: %w", err)
	}
	sum := sha256.Sum256([]byte(data))
	return filepath.Join(root, "go-instance-"+hex.EncodeToString(sum[:])[:32]), nil
}

func backupLimits(cfg config.Config) backup.Limits {
	b := cfg.Backup
	l := backup.Limits{MaxMembers: int(min(b.MaxMembers, 1<<31-1)), MaxFileSize: b.MaxFileSize, MaxTotalSize: b.MaxTotalSize,
		MaxCompressionRatio: int(min(b.MaxCompressionRatio, 1<<31-1)), MaxManifestSize: b.MaxManifestSize,
		UploadMaxSize: b.UploadMaxSize, OperationTimeout: b.OperationTimeout}
	if l.MaxMembers <= 0 {
		return backup.DefaultLimits
	}
	return l
}

// backupInstallation describes the live installation for a restore: the
// active SECRET_KEY and keyring material, every schema, and the restore
// semantics a staged database gets (restorePrepare).
func backupInstallation(cfg config.Config, lookup config.LookupFunc, live *store.DB, work string) (*backup.Installation, error) {
	_, legacyErr := os.Lstat(filepath.Join(cfg.DataDir, "app.db"))
	path, material, err := keyring.MaterialLocation(cfg.DataDir, legacyErr == nil)
	if err != nil {
		return nil, err
	}
	o, err := migrationOptions(cfg, lookup)
	if err != nil {
		return nil, err
	}
	return &backup.Installation{DataDir: cfg.DataDir, SecretKey: cfg.SecretKey.Bytes(),
		EnvironmentSecret: cfg.SecretSource == config.SecretFromEnvironment, AdoptSecret: cfg.SecretSource == config.SecretFromFile,
		MaterialPath: path, Material: material,
		Schemas: schemas(), Prepare: restorePrepare(live), Probes: []backup.Probe{vault.ProbeSealed, totp.ProbeSealed},
		Limits: backupLimits(cfg), Legacy: &legacy.Restorer{Options: o, Work: work}, Work: work}, nil
}

// restorePrepare is the restore semantics of a staged database (the
// Python release's restore_sanitizer and mark_restore_recovery, and
// specification 5.6): an export loses its remote credentials and sets the
// recovery check notice; every generation is raised, every session and
// persistent terminal session ends; and the installation keeps its own
// migration state and records the key id of the restored records.
func restorePrepare(live *store.DB) func(ctx context.Context, tx *store.Tx, p backup.Prepared) error {
	return func(ctx context.Context, tx *store.Tx, p backup.Prepared) error {
		if p.Export {
			if _, err := vault.DropRemoteCredentialsTx(ctx, tx); err != nil {
				return err
			}
			if err := settings.MarkRestoredTx(ctx, tx, p.RestoredAt); err != nil {
				return err
			}
		}
		in, err := legacy.ReadInstallation(ctx, live)
		if err != nil {
			return err
		}
		return errors.Join(accounts.RaiseAllGenerationsTx(ctx, tx), session.ResetTx(ctx, tx),
			terminal.ForgetPersistentTx(ctx, tx), in.CarryTx(ctx, tx, p.KeyID))
	}
}

// backupAudit writes the backup events to the audit log.
type backupAudit struct{ sys *system }

func (a backupAudit) Security(event string, kv ...any) {
	if a.sys != nil && a.sys.audit != nil {
		a.sys.audit.Security(event, kv...)
	}
}

// backupLimiter applies RATELIMIT_BACKUP_* per administrator, like the
// re-authentication limiter of the Python release.
func backupLimiter(cfg config.Config, l *auth.Limiter) backup.Limiter {
	if !cfg.RateLimits.Enabled || l == nil {
		return nil
	}
	rules := map[string]auth.Rule{
		"backup_create":   auth.ParseRule(cfg.Backup.RateCreate, auth.Rule{Limit: 3, Window: time.Hour}),
		"backup_upload":   auth.ParseRule(cfg.Backup.RateUpload, auth.Rule{Limit: 5, Window: time.Hour}),
		"backup_download": auth.ParseRule(cfg.Backup.RateDownload, auth.Rule{Limit: 10, Window: time.Hour}),
		"backup_restore":  auth.ParseRule(cfg.Backup.RateRestore, auth.Rule{Limit: 3, Window: time.Hour}),
	}
	return func(userID int64, _, kind string) bool {
		ok, _ := l.AllowAccount("backup:"+kind+":"+strconv.FormatInt(userID, 10), rules[kind])
		return ok
	}
}

// wireBackup registers the online backup, upload and restore routes and
// the recovery check.
func wireBackup(sys *system) error {
	cfg := sys.cfg
	ns, err := backupNamespace(cfg)
	if err != nil {
		return err
	}
	ops, err := backup.NewOperations(ns, cfg.Backup.OperationTimeout, cfg.Backup.DownloadTTL)
	if err != nil {
		return fmt.Errorf("backup operations: %w", err)
	}
	inst, err := backupInstallation(cfg, sys.lookup, sys.db, ns)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	audit := backupAudit{sys}
	h := &backup.HTTP{Ops: ops, Inst: inst, StepUp: sys.stepup, Limit: backupLimiter(cfg, sys.limiter), Audit: audit,
		Logger: sys.log, Limits: inst.Limits, Timeout: cfg.Backup.OperationTimeout, Background: ctx,
		Export: func(ctx context.Context, path, work string) (backup.Verified, error) {
			return backup.Export(ctx, backup.ExportRequest{Source: sys.db, Path: path, Work: work,
				Scrub: exportScrubbers(), SecretKey: cfg.SecretKey.Bytes(), Material: inst.Material, KeyID: sys.ring.KeyID(), Release: buildinfo.Read().Version,
				Now: time.Now().UTC(), Probes: inst.Probes, Limits: inst.Limits})
		},
		Restore: &backup.RestoreRunner{Inst: inst, Ops: ops, Maintenance: &sys.maintenance, Drain: sys.drainForRestore,
			Restart: sys.requestRestart, Audit: audit, Logger: sys.log}}
	swept := make(chan struct{})
	sys.closers = append(sys.closers, func() error {
		cancel()
		<-swept
		h.Wait()
		return ops.Close()
	})
	mux := sys.edge.Mux()
	h.Register(mux)
	if err := sys.edge.StreamBody(backup.UploadPattern); err != nil {
		return err
	}
	rc := &recoveryCheck{sys: sys}
	mux.HandleFunc("GET /api/account/recovery-check", rc.get)
	mux.HandleFunc("POST /api/account/recovery-check", rc.review)
	go func() {
		defer close(swept)
		t := time.NewTicker(max(5*time.Second, min(time.Minute, cfg.Backup.DownloadTTL/2)))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ops.Sweep()
			}
		}
	}()
	return nil
}

// drainForRestore ends the long-lived work before a restore is staged:
// realtime connections close with 4503, terminal sessions end (tmux
// sessions stay on the hosts), background jobs stop.
func (s *system) drainForRestore(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.shutdownGrace())
	defer cancel()
	return s.drain(ctx)
}
