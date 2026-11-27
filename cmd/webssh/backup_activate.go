package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
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
