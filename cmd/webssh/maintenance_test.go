package main

import (
	"context"
	"errors"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/fault"
)

func TestMaintenanceOneReasonAtATime(t *testing.T) {
	var m maintenance
	closed := 0
	m.setCloser(func(string) int { closed++; return 1 })
	leave, err := m.Enter(t.Context(), backup.MaintenanceRotation)
	if err != nil {
		t.Fatal(err)
	}
	if r, on := m.Active(); !on || r != backup.MaintenanceRotation || !m.Load() || closed != 1 {
		t.Fatalf("active %q %t, closed %d", r, on, closed)
	}
	if _, err := m.Enter(t.Context(), backup.MaintenanceRestore); !fault.Is(err, fault.Busy) {
		t.Fatalf("second reason: %v", err)
	}
	leave()
	leave() // idempotent
	if _, on := m.Active(); on || m.Load() {
		t.Fatal("still in maintenance after leave")
	}
	if _, err := m.Enter(t.Context(), "other"); !fault.Is(err, fault.InvalidValue) {
		t.Fatalf("unknown reason: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.Enter(ctx, backup.MaintenanceRestore); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}

// A changed legacy source takes over the mode and is never left, not even
// by the leave of the reason it replaced.
func TestMaintenanceSourceChangeSticks(t *testing.T) {
	var m maintenance
	leave, err := m.Enter(t.Context(), backup.MaintenanceRestore)
	if err != nil {
		t.Fatal(err)
	}
	if !m.enterPermanent(backup.MaintenanceSourceChange) {
		t.Fatal("source change did not take over")
	}
	if m.enterPermanent(backup.MaintenanceSourceChange) {
		t.Fatal("second source change switched again")
	}
	leave()
	if r, on := m.Active(); !on || r != backup.MaintenanceSourceChange {
		t.Fatalf("after leave: %q %t", r, on)
	}
	var n maintenance
	leave, err = n.Enter(t.Context(), backup.MaintenanceSourceChange)
	if err != nil {
		t.Fatal(err)
	}
	leave()
	if !n.Load() {
		t.Fatal("legacy_source_changed was left")
	}
}
