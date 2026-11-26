// Package backuptest holds test doubles of the contracts of
// internal/backup: the maintenance switch and the restorer of Python
// backups. Only test files import it.
package backuptest

import (
	"context"
	"sync"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/fault"
)

// Maintenance is a backup.Maintenance with the rules of the contract: one
// reason at a time, and legacy_source_changed is never left.
type Maintenance struct {
	mu     sync.Mutex
	reason backup.MaintenanceReason
	on     bool
	// Entered records every reason that was entered.
	Entered []backup.MaintenanceReason
}

var _ backup.Maintenance = (*Maintenance)(nil)

// Enter implements backup.Maintenance.
func (m *Maintenance) Enter(_ context.Context, reason backup.MaintenanceReason) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.on {
		return nil, fault.New(fault.Busy, "")
	}
	m.on, m.reason = true, reason
	m.Entered = append(m.Entered, reason)
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.reason != backup.MaintenanceSourceChange {
				m.on, m.reason = false, ""
			}
		})
	}, nil
}

// Active implements backup.Maintenance.
func (m *Maintenance) Active() (backup.MaintenanceReason, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reason, m.on
}

// Restorer is a backup.LegacyRestorer that returns Outcome or Err and
// records the requests.
type Restorer struct {
	Outcome backup.LegacyOutcome
	Err     error

	mu       sync.Mutex
	Requests []backup.LegacyRestore
}

var _ backup.LegacyRestorer = (*Restorer)(nil)

// RestoreLegacy implements backup.LegacyRestorer.
func (r *Restorer) RestoreLegacy(ctx context.Context, req backup.LegacyRestore) (backup.LegacyOutcome, error) {
	if err := ctx.Err(); err != nil {
		return backup.LegacyOutcome{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Requests = append(r.Requests, req)
	if r.Err != nil {
		return backup.LegacyOutcome{}, r.Err
	}
	return r.Outcome, nil
}
