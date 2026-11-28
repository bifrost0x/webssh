package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/buildinfo"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

const offlineMessage = "Stop every WebSSH application process first, then repeat with --confirm-offline."

// refuseOnline is the refusal of the offline commands, worded as in the
// Python release.
func refuseOnline(s streams) int {
	write(s.stderr, "Error: "+offlineMessage+"\n")
	return 1
}

// runBackup is `webssh backup create|verify|restore` (C-BAK-07, the
// commands of app/cli.py with the same options).
func runBackup(ctx context.Context, args []string, s streams) int {
	if len(args) == 0 {
		return usageError(s.stderr, "backup needs one of the subcommands create, verify and restore")
	}
	switch args[0] {
	case "create":
		return backupCreate(ctx, args[1:], s)
	case "verify":
		return backupVerify(ctx, args[1:], s)
	case "restore":
		return backupRestore(ctx, args[1:], s)
	}
	return usageError(s.stderr, fmt.Sprintf("unknown backup subcommand %q", args[0]))
}

func backupFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("backup "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseInterleaved parses flags before and after the positional
// arguments, as click does.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos, args = append(pos, args[0]), args[1:]
	}
}

func backupCreate(ctx context.Context, args []string, s streams) int {
	fs := backupFlags("create")
	dest := fs.String("destination", "", "")
	offline := fs.Bool("confirm-offline", false, "")
	without := fs.Bool("without-secret-key", false, "")
	include := fs.Bool("include-secret-key", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*without && *include) {
		return usageError(s.stderr, "usage: webssh backup create [--destination ARCHIVE] [--without-secret-key | --include-secret-key] --confirm-offline")
	}
	if !*offline {
		return refuseOnline(s)
	}
	cfg, err := loadConfig()
	if err != nil {
		return fail(s, err)
	}
	g, err := openGoData(ctx, cfg)
	if err != nil {
		return fail(s, err)
	}
	defer g.Close()
	if g.startup == nil {
		return refuseOnline(s)
	}
	path, err := backupDestination(cfg, *dest, time.Now())
	if err != nil {
		return fail(s, err)
	}
	ns, err := backupNamespace(cfg)
	if err != nil {
		return fail(s, err)
	}
	if err := os.MkdirAll(ns, 0o700); err != nil {
		return fail(s, err)
	}
	work, err := os.MkdirTemp(ns, "cli-")
	if err != nil {
		return fail(s, err)
	}
	defer os.RemoveAll(work)
	omit := *without || (envSecret(cfg) && !*include)
	legacy := legacyPresent(cfg)
	_, material, err := keyring.MaterialLocation(cfg.DataDir, legacy)
	if err != nil {
		return fail(s, err)
	}
	v, err := backup.Export(ctx, backup.ExportRequest{Source: g.db, Path: path, Work: work, Scrub: exportScrubbers(),
		SecretKey: cfg.SecretKey.Bytes(), WithoutSecretKey: omit,
		WithoutMaterial: leaveOutMaterial(cfg.SecretSource, omit, legacy), Material: material, KeyID: g.ring.KeyID(),
		Release: buildinfo.Read().Version, Now: time.Now().UTC(), Probes: []backup.Probe{vault.ProbeSealed},
		Limits: backupLimits(cfg)})
	if err != nil {
		return fail(s, err)
	}
	g.audit.Security("BACKUP_CREATE_SUCCESS", "file_count", len(v.Manifest.Files))
	msg := fmt.Sprintf("Backup created and verified: %s (%d files, format v%d, data schema %d)\n", path,
		len(v.Manifest.Files), v.Manifest.Version, v.Manifest.Version)
	switch {
	case !omit:
		msg += "It contains SECRET_KEY; keep it off this host or create it with --without-secret-key.\n"
	case leaveOutMaterial(cfg.SecretSource, omit, legacy):
		msg += "SECRET_KEY and the keyring material are not in the archive while the 3.3 data exists; it restores only on a host that has both.\n"
	case !*without:
		msg += "SECRET_KEY comes from the environment and is not in the archive; restore it with the same SECRET_KEY, or add it with --include-secret-key.\n"
	}
	return write(s.stdout, msg)
}

func exportScrubbers() []backup.Scrubber {
	return []backup.Scrubber{func(ctx context.Context, tx *store.Tx) error {
		_, err := vault.DropRemoteCredentialsTx(ctx, tx)
		return err
	}}
}

// envSecret reports a SECRET_KEY from the environment. Exports leave it
// out by default: the Python release never wrote such a key to DATA_DIR,
// so its archives never held it, and operators keep it off the volume
// for that reason.
func envSecret(cfg config.Config) bool {
	return cfg.SecretSource == config.SecretFromEnvironment
}

// leaveOutMaterial reports whether an archive that leaves out SECRET_KEY
// leaves out the keyring material too. That is the case only while the
// 3.3 data exists and the key is DATA_DIR/secret_key: every Python export
// of the way back holds that file, and with the material of this archive
// it would open every sealed secret (migration specification 2.2).
// Otherwise the material stays in, so a lost volume can be restored with
// the same SECRET_KEY.
func leaveOutMaterial(source config.SecretSource, omitSecret, legacy bool) bool {
	return omitSecret && legacy && source == config.SecretFromFile
}

func legacyPresent(cfg config.Config) bool {
	_, err := os.Lstat(filepath.Join(cfg.DataDir, "app.db"))
	return err == nil
}

// backupDestination is the archive to create: the given path, or a new
// name next to DATA_DIR when its parent is writable, otherwise in the
// backup namespace (default_backup_directory). Never inside DATA_DIR.
func backupDestination(cfg config.Config, dest string, now time.Time) (string, error) {
	data, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return "", err
	}
	if dest == "" {
		dir := filepath.Dir(data)
		if probe, err := os.MkdirTemp(dir, ".webssh-backup-probe-"); err == nil {
			_ = os.Remove(probe)
		} else if dir, err = backupNamespace(cfg); err != nil {
			return "", err
		}
		return filepath.Join(dir, backup.ArchiveName(now)), nil
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	if abs == data || strings.HasPrefix(abs, data+string(filepath.Separator)) {
		return "", errors.New("backup destination must be outside DATA_DIR")
	}
	return abs, nil
}

// cliInstallation is the installation as the offline commands see it:
// the live database (nil on a new installation) and its material,
// created when a new installation has none.
func cliInstallation(cfg config.Config, live *store.DB, create bool) (*backup.Installation, error) {
	ns, err := backupNamespace(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(ns, 0o700); err != nil {
		return nil, err
	}
	if create {
		if _, err := keyring.LoadOrCreateMaterial(cfg.DataDir, legacyPresent(cfg)); err != nil {
			return nil, err
		}
	}
	return backupInstallation(cfg, os.LookupEnv, live, ns)
}

func backupVerify(ctx context.Context, args []string, s streams) int {
	pos, err := parseInterleaved(backupFlags("verify"), args)
	if err != nil || len(pos) != 1 {
		return usageError(s.stderr, "usage: webssh backup verify ARCHIVE")
	}
	cfg, err := loadConfig()
	if err != nil {
		return fail(s, err)
	}
	in, err := cliInstallation(cfg, nil, false)
	if err != nil {
		return fail(s, err)
	}
	sum, err := backup.Inspect(ctx, in, pos[0])
	if err != nil {
		return fail(s, err)
	}
	status := "restore incompatible"
	switch {
	case sum.Compatible && sum.Legacy:
		status = "restore compatible (legacy)"
	case sum.Compatible:
		status = "restore compatible"
	}
	return write(s.stdout, fmt.Sprintf("Backup verified (%d files, format v%d, data schema %d, %s).\n",
		sum.FileCount, sum.FormatVersion, sum.DataSchemaVersion, status))
}

func backupRestore(ctx context.Context, args []string, s streams) int {
	fs := backupFlags("restore")
	offline := fs.Bool("confirm-offline", false, "")
	recovery := fs.Bool("recovery-snapshot", false, "")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 1 {
		return usageError(s.stderr, "usage: webssh backup restore ARCHIVE --confirm-offline [--recovery-snapshot]")
	}
	if !*offline {
		return refuseOnline(s)
	}
	archive, err := filepath.Abs(pos[0])
	if err != nil {
		return fail(s, err)
	}
	if info, err := os.Stat(archive); err != nil || !info.Mode().IsRegular() { // #nosec G703 -- the archive the operator names on the command line
		return fail(s, fmt.Errorf("the archive %s is not a readable file", pos[0]))
	}
	cfg, err := loadConfig()
	if err != nil {
		return fail(s, err)
	}
	o, err := migrationOptions(cfg, os.LookupEnv)
	if err != nil {
		return fail(s, err)
	}
	var j *backup.Journal
	var kept []string
	err = legacy.Exclusive(ctx, o, func(ctx context.Context) error {
		var err error
		j, kept, err = restoreOffline(ctx, cfg, archive, *recovery)
		return err
	})
	if se, ok := errors.AsType[*legacy.StopError](err); ok && se.Code == legacy.CodeLocked {
		return refuseOnline(s)
	}
	if err != nil {
		return fail(s, err)
	}
	if j == nil || j.State != backup.RestoreSucceeded {
		msg := "the restore did not complete"
		if j != nil {
			msg = j.Message
		}
		return fail(s, errors.New(msg))
	}
	msg := "Backup restored and verified.\n"
	if len(kept) > 0 {
		msg += "The files of the earlier restore whose rollback failed are kept; remove them once they are no longer needed:\n  " +
			strings.Join(kept, "\n  ") + "\n"
	}
	return write(s.stdout, msg)
}

// restoreOffline stages the archive against the live installation and
// activates it, with the Go lock held. After a restore whose rollback
// failed, the files that restore kept (the previous and the restored
// database) are set aside first and returned, so that neither this
// restore nor a later start removes them.
func restoreOffline(ctx context.Context, cfg config.Config, archive string, recovery bool) (*backup.Journal, []string, error) {
	goDir := filepath.Join(cfg.DataDir, keyring.GoDirName)
	dbPath := filepath.Join(goDir, keyring.DatabaseName)
	_, dbErr := os.Lstat(dbPath)
	fresh := errors.Is(dbErr, fs.ErrNotExist)
	if fresh && legacyPresent(cfg) {
		return nil, nil, errNotMigrated
	}
	var kept []string
	if blocked, _ := backup.Blocked(goDir); blocked {
		var err error
		if kept, err = backup.SetAsideLeftovers(cfg.DataDir); err != nil {
			return nil, kept, err
		}
	}
	if err := os.MkdirAll(goDir, 0o700); err != nil {
		return nil, nil, err
	}
	var live *store.DB
	if !fresh {
		var err error
		if live, err = store.Open(ctx, dbPath, store.Options{}); err != nil {
			return nil, nil, fmt.Errorf("the Go database does not open: %w", err)
		}
	}
	closeLive := func() error {
		if live == nil {
			return nil
		}
		err := live.Close()
		live = nil
		return err
	}
	defer closeLive()
	in, err := cliInstallation(cfg, live, fresh)
	if err != nil {
		return nil, nil, err
	}
	id := strings.ReplaceAll(fmt.Sprintf("cli-%d", time.Now().UnixNano()), "-", "_")
	if err := backup.Begin(goDir, id, time.Now()); err != nil {
		return nil, nil, err
	}
	st, err := backup.Stage(ctx, in, backup.StageRequest{OperationID: id, Archive: archive, RecoverySnapshot: recovery})
	if err != nil {
		return nil, nil, errors.Join(err, backup.Fail(goDir, id, "restore_failed", time.Now()))
	}
	if err := closeLive(); err != nil {
		return nil, nil, err
	}
	if err := backup.Commit(goDir, st, in, time.Now()); err != nil {
		return nil, nil, err
	}
	j, err := backup.Activate(cfg.DataDir, time.Now)
	return j, kept, err
}
