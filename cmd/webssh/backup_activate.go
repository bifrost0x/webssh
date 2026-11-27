package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
)

// activateRestore is the legacy.Options.BeforeStart hook: with the Go
// lock held and before anything opens the Go database, it completes or
// rolls back a restore that a previous run staged (backup.Activate). A
// restore whose rollback failed, or an unreadable journal, does not stop
// the start: the server then serves in maintenance (restoreBlocked)
// until `webssh backup restore` resolves it, as the Python release does.
func activateRestore(dataDir string, log *slog.Logger) func(context.Context) error {
	return func(context.Context) error {
		j, err := backup.Activate(dataDir, time.Now)
		switch {
		case j == nil && err != nil:
			return err
		case j == nil:
			return nil
		case j.State == backup.RestoreSucceeded:
			log.Info("restore", "state", string(j.State), "operation", j.OperationID, "kind", string(j.Kind), "message", j.Message)
		case j.State.Blocking():
			log.Error("restore", "state", string(j.State), "operation", j.OperationID, "message", j.Message, "err", err)
		case err != nil:
			log.Error("restore", "state", string(j.State), "operation", j.OperationID, "message", j.Message, "err", err)
		}
		return nil
	}
}

// restoreBlocked reports a restore that keeps the installation in
// maintenance after the start.
func restoreBlocked(dataDir string) (bool, string) {
	return backup.Blocked(filepath.Join(dataDir, keyring.GoDirName))
}

// activateSecretRestore activates, before the configuration is used, a
// restore that replaces DATA_DIR/secret_key with the archive's SECRET_KEY:
// the Go lock is taken and released again around backup.Activate. The
// caller reads the configuration again when it returns true, so that the
// start goes on with the restored secret (the Python release read the
// restored secret_key file at its next start).
func activateSecretRestore(ctx context.Context, cfg config.Config, lookup config.LookupFunc, log *slog.Logger) (bool, error) {
	j, err := backup.ReadJournal(filepath.Join(cfg.DataDir, keyring.GoDirName))
	if err != nil || j == nil || j.State != backup.RestoreInProgress || !j.Secret {
		// An unreadable journal is reported by the activation at the start.
		return false, nil
	}
	o, err := migrationOptions(cfg, lookup)
	if err != nil {
		return false, err
	}
	o.BeforeStart = activateRestore(cfg.DataDir, log)
	if err := legacy.Exclusive(ctx, o, func(context.Context) error { return nil }); err != nil {
		return false, fmt.Errorf("activate the restore: %w", err)
	}
	return true, nil
}
