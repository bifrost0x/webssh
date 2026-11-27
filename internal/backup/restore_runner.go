package backup

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// RestoreRunner runs a confirmed online restore (C-BAK-03): the server
// enters maintenance, the journal records the preparation, long-lived
// connections end, the archive is staged and committed, and the server
// restarts; the next start activates the staged database (Activate)
// before anything opens it. A failure before the commit leaves the live
// state as it was and ends maintenance.
type RestoreRunner struct {
	Inst        *Installation
	Ops         *Operations
	Maintenance Maintenance
	// Drain ends the realtime connections, terminal sessions and
	// background jobs, so that nothing writes while the restore runs.
	Drain func(ctx context.Context) error
	// Restart asks the server to restart; the start activates the
	// restore.
	Restart func()
	Audit   Auditor
	Logger  *slog.Logger
	Now     func() time.Time
}

func (rr *RestoreRunner) now() time.Time {
	if rr.Now != nil {
		return rr.Now()
	}
	return time.Now()
}

// Start enters maintenance and runs the restore of op in the background
// (tracked by wg). It fails without changing anything when maintenance
// is held by another reason.
func (rr *RestoreRunner) Start(ctx context.Context, op Operation, user string, wg *sync.WaitGroup) error {
	if rr.Inst == nil || rr.Maintenance == nil || rr.Restart == nil {
		return errors.New("backup: the restore is not wired")
	}
	leave, err := rr.Maintenance.Enter(ctx, MaintenanceRestore)
	if err != nil {
		return err
	}
	goDir := rr.Inst.goDir()
	if err := Begin(goDir, op.ID, rr.now()); err != nil {
		leave()
		return err
	}
	wg.Go(func() { rr.run(ctx, op, user, leave) })
	return nil
}

func (rr *RestoreRunner) run(ctx context.Context, op Operation, user string, leave func()) {
	goDir := rr.Inst.goDir()
	err := rr.stage(ctx, op)
	if err == nil {
		if rr.Audit != nil {
			rr.Audit.Security("RESTORE_STAGED", "user", user)
		}
		rr.Restart()
		return
	}
	code := "restore_failed"
	if errors.Is(err, ErrSecretMismatch) || errors.Is(err, ErrKeyMismatch) {
		code = "secret_key_mismatch"
	}
	failErr := Fail(goDir, op.ID, code, rr.now())
	rr.logger().Error("restore failed before persistent state changed", "err", errors.Join(err, failErr))
	if rr.Audit != nil {
		rr.Audit.Security("RESTORE_FAILED", "user", user, "rollback_failed", false)
	}
	_ = rr.Ops.Remove(op.ID)
	if failErr != nil {
		// Without a readable journal the start decides; maintenance
		// stays on until then.
		rr.Restart()
		return
	}
	leave()
	// Realtime connections and terminals were ended for the restore; a
	// restart brings them back in a defined state.
	rr.Restart()
}

func (rr *RestoreRunner) stage(ctx context.Context, op Operation) error {
	if rr.Drain != nil {
		if err := rr.Drain(ctx); err != nil {
			return err
		}
	}
	st, err := Stage(ctx, rr.Inst, StageRequest{OperationID: op.ID, Archive: op.Archive(), Portable: true})
	if err != nil {
		return err
	}
	if err := Commit(rr.Inst.goDir(), st, rr.Inst, rr.now()); err != nil {
		return errors.Join(err, discardStaged(st))
	}
	return nil
}

func (rr *RestoreRunner) logger() *slog.Logger {
	if rr.Logger != nil {
		return rr.Logger
	}
	return slog.Default()
}
