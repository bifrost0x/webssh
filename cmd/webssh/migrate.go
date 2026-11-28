package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/platform"
	"github.com/bifrost0x/webssh/internal/vault"
)

// runMigrate is `webssh migrate --dry-run` and `webssh migrate --replace`
// (migration specification, section 5.4). Both need the service stopped.
func runMigrate(ctx context.Context, args []string, s streams) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "")
	replace := fs.Bool("replace", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dryRun == *replace {
		return usageError(s.stderr, "migrate needs exactly one of --dry-run and --replace")
	}
	load := loadConfig
	if *dryRun {
		load = loadConfigReadOnly
	}
	cfg, err := load()
	if err != nil {
		return fail(s, err)
	}
	o, err := migrationOptions(cfg, os.LookupEnv)
	if err != nil {
		return fail(s, err)
	}
	if *dryRun {
		report, err := legacy.DryRun(ctx, o)
		if err != nil {
			return fail(s, err)
		}
		return printJSON(s, report)
	}
	if err := requireCompleteRegistry(o.Registry); err != nil {
		return fail(s, err)
	}
	out, err := legacy.Replace(ctx, o)
	if err != nil {
		return fail(s, err)
	}
	printWarnings(s, out.Warnings)
	if out.Database != "" {
		write(s.stdout, "The replaced Go database is kept in "+out.Database+".\n")
	}
	write(s.stdout, "Migration report: "+out.ReportPath+"\n")
	return 0
}

// loadConfigReadOnly resolves the configuration like loadConfig without
// writing to DATA_DIR, for `migrate --dry-run`: the directory and its
// subdirectories are not created or narrowed, and no secret is
// generated. An interrupted secret rotation or restore of the secret
// would have to be completed first, which writes; the dry run refuses
// instead and names the way out.
func loadConfigReadOnly() (config.Config, error) {
	cfg, _, err := config.BootstrapReadOnly(os.LookupEnv, platform.CheckDataDir)
	if err != nil {
		return cfg, err
	}
	goDir := filepath.Join(cfg.DataDir, keyring.GoDirName)
	if _, err := os.Lstat(filepath.Join(goDir, backup.PendingSecretName)); err == nil {
		return cfg, errors.New("an interrupted rotation of SECRET_KEY is pending; start WebSSH once to complete it, then run the dry run")
	}
	if j, err := backup.ReadJournal(goDir); err == nil && j != nil && j.State == backup.RestoreInProgress && j.Secret {
		return cfg, errors.New("a restore that replaces SECRET_KEY is pending; start WebSSH once to complete it, then run the dry run")
	}
	return cfg, nil
}

// runLegacy is `webssh legacy purge [--backup-to DIR] [--skip-backup]
// [--yes]` (section 5.9).
func runLegacy(ctx context.Context, args []string, s streams) int {
	if len(args) == 0 || args[0] != "purge" {
		return usageError(s.stderr, "legacy needs the subcommand purge")
	}
	fs := flag.NewFlagSet("legacy purge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	backupTo := fs.String("backup-to", "", "")
	skip := fs.Bool("skip-backup", false, "")
	yes := fs.Bool("yes", false, "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || (*skip && *backupTo != "") {
		return usageError(s.stderr, "usage: webssh legacy purge [--backup-to DIR | --skip-backup] [--yes]")
	}
	cfg, err := loadConfig()
	if err != nil {
		return fail(s, err)
	}
	mo, err := migrationOptions(cfg, os.LookupEnv)
	if err != nil {
		return fail(s, err)
	}
	o := legacy.PurgeOptions{Options: mo, BackupDir: *backupTo, SkipBackup: *skip, Backup: purgeBackupWriter(envSecret(cfg)),
		Confirm: func(p legacy.PurgePlan) bool { return confirmPurge(s, p, *yes) }}
	out, err := legacy.Purge(ctx, o)
	if errors.Is(err, legacy.ErrPurgeAborted) {
		write(s.stderr, "Aborted!\n")
		return 1
	}
	if err != nil {
		return fail(s, err)
	}
	printWarnings(s, out.Warnings)
	if out.State == legacy.S4 {
		write(s.stdout, "The legacy data was already purged.\n")
		return 0
	}
	if out.Backup != "" {
		write(s.stdout, "Backup written and verified: "+out.Backup+"\nIt contains SECRET_KEY and the keyring "+
			"material; keep it off this host.\n")
	}
	write(s.stdout, fmt.Sprintf("Legacy data removed (%d files). The way back to the Python release no longer exists.\n", out.Removed))
	return 0
}

// confirmPurge shows what the purge removes, naming the legacy paths the
// migration kept in place (they go into the backup), and asks unless
// --yes was given.
func confirmPurge(s streams, p legacy.PurgePlan, yes bool) bool {
	if len(p.Kept) > 0 {
		write(s.stdout, "The migration kept these legacy paths in place; Go did not take them over. They are removed "+
			"with the Python data and go into the backup:\n")
		for _, k := range p.Kept {
			write(s.stdout, fmt.Sprintf("  %s (%s, %d files)\n", k.Path, k.Reason, k.Files))
		}
	}
	if yes {
		return true
	}
	msg := fmt.Sprintf("Remove the Python data from the data directory (%d files)? This ends the way back to the Python release.", p.Files)
	if p.SkipBackup {
		msg += " No backup is written."
	}
	write(s.stdout, msg+" [y/N]: ")
	var line strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := s.stdin.Read(buf)
		if n == 1 && buf[0] != '\n' {
			line.WriteByte(buf[0])
			continue
		}
		if n == 1 || err != nil {
			break
		}
	}
	answer := strings.ToLower(strings.TrimSpace(line.String()))
	return answer == "y" || answer == "yes"
}

// purgeBackupWriter writes the purge backup and verifies it by reading it
// back, including one sealed SSH key or TOTP secret when there is one.
// A SECRET_KEY from the environment stays out of the archive, as in every
// export (envSecret); the archive then verifies with that key.
func purgeBackupWriter(omitSecret bool) func(context.Context, legacy.BackupRequest) (string, error) {
	return func(ctx context.Context, req legacy.BackupRequest) (string, error) {
		c := backup.Contents{Database: req.Database, SecretKey: req.Secret, Material: req.Material,
			KeyID: req.KeyID, Release: req.Release, Reason: "legacy-purge", Now: req.Now, DataDir: req.DataDir, Legacy: req.Legacy}
		if omitSecret {
			c.SecretKey = nil
		}
		path, err := backup.Write(req.Dir, c)
		if err != nil {
			return "", err
		}
		v, err := backup.VerifyWith(ctx, path, backup.VerifyOptions{Secret: req.Secret, RequireSecret: !omitSecret,
			Probes: []backup.Probe{vault.ProbeSealed, totp.ProbeSealed}})
		if err == nil {
			err = holdsLegacy(v.Manifest, req.Legacy)
		}
		if err != nil {
			// The archive may hold SECRET_KEY; one that does not
			// verify is not left behind.
			return "", errors.Join(err, os.Remove(path))
		}
		return path, nil
	}
}

// holdsLegacy checks that the verified archive holds every kept legacy
// file the purge removes.
func holdsLegacy(m backup.Manifest, legacyFiles []string) error {
	have := map[string]bool{}
	for _, f := range m.Files {
		have[f.Name] = true
	}
	for _, p := range legacyFiles {
		if !have["data/"+p] {
			return fmt.Errorf("backup: the archive lacks the kept legacy file %s", p)
		}
	}
	return nil
}

func printWarnings(s streams, ws []legacy.Warning) {
	for _, w := range ws {
		write(s.stderr, "Warning: "+w.Message+"\n")
	}
}

func printJSON(s streams, v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return fail(s, err)
	}
	return write(s.stdout, string(b)+"\n")
}

// fail prints a refusal or error; a STOP prints its message, which names
// the way out, and its code.
func fail(s streams, err error) int {
	if se, ok := errors.AsType[*legacy.StopError](err); ok {
		write(s.stderr, "Error: "+se.Message+" ("+se.Code+")\n")
		return 1
	}
	write(s.stderr, "Error: "+err.Error()+"\n")
	return 1
}
