package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
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
	cfg, err := loadConfig()
	if err != nil {
		return fail(s, err)
	}
	o := migrationOptions(cfg)
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
	if !*yes && !confirmPurge(s, *skip) {
		write(s.stderr, "Aborted!\n")
		return 1
	}
	cfg, err := loadConfig()
	if err != nil {
		return fail(s, err)
	}
	o := legacy.PurgeOptions{Options: migrationOptions(cfg), BackupDir: *backupTo, SkipBackup: *skip, Backup: writeVerifiedBackup}
	out, err := legacy.Purge(ctx, o)
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

func confirmPurge(s streams, skip bool) bool {
	msg := "Remove the Python data from the data directory? This ends the way back to the Python release."
	if skip {
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

// writeVerifiedBackup writes the purge backup and verifies it by reading
// it back, including one sealed SSH key or TOTP secret when there is one.
func writeVerifiedBackup(ctx context.Context, req legacy.BackupRequest) (string, error) {
	path, err := backup.Write(req.Dir, backup.Contents{Database: req.Database, SecretKey: req.Secret, Material: req.Material,
		KeyID: req.KeyID, Release: req.Release, Reason: "legacy-purge", Now: req.Now})
	if err != nil {
		return "", err
	}
	if _, err := backup.Verify(ctx, path, vault.ProbeSealed, totp.ProbeSealed); err != nil {
		// The archive holds SECRET_KEY; one that does not verify is
		// not left behind.
		return "", errors.Join(err, os.Remove(path))
	}
	return path, nil
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
