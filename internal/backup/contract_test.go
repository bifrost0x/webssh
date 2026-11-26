package backup_test

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/backup/backuptest"
	"github.com/bifrost0x/webssh/internal/fault"
)

func TestStates(t *testing.T) {
	t.Parallel()
	for s, want := range map[backup.OperationStatus]bool{
		backup.StatusPending: true, backup.StatusRunning: true, backup.StatusUploading: true,
		backup.StatusVerifying: true, backup.StatusDownloading: true, backup.StatusRestoring: true,
		backup.StatusVerified: false, backup.StatusReady: false, backup.StatusFailed: false,
	} {
		if s.Active() != want {
			t.Errorf("%s: Active %v", s, !want)
		}
	}
	// The blocking states of the Python release (A10).
	for s, want := range map[backup.RestoreState]bool{
		backup.RestorePreparing: true, backup.RestoreInProgress: true, backup.RestoreRollbackFailed: true,
		backup.RestoreSucceeded: false, backup.RestoreFailed: false,
	} {
		if s.Blocking() != want {
			t.Errorf("%s: Blocking %v", s, !want)
		}
	}
}

func TestMaintenanceFake(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	m := &backuptest.Maintenance{}
	leave, err := m.Enter(ctx, backup.MaintenanceRestore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Enter(ctx, backup.MaintenanceRotation); !fault.Is(err, fault.Busy) {
		t.Fatalf("second reason: %v", err)
	}
	leave()
	leave()
	if _, on := m.Active(); on {
		t.Fatal("maintenance still on after leave")
	}
	leave, _ = m.Enter(ctx, backup.MaintenanceSourceChange)
	leave()
	if r, on := m.Active(); !on || r != backup.MaintenanceSourceChange {
		t.Fatal("a changed legacy source left maintenance before a restart")
	}
}
