package main

import (
	"context"
	"sync"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/fault"
)

// maintenanceSwitch is the server's maintenance mode (backup.Maintenance):
// while it is on, the HTTP entry answers only the probes and the
// exempted status routes, so that new realtime connections are refused
// as well. One reason holds it at a time; legacy_source_changed is left
// only by a restart. The restore, the secret rotation and the legacy
// source watch share it.
type maintenanceSwitch struct {
	mu     sync.Mutex
	on     bool
	reason backup.MaintenanceReason
}

var _ backup.Maintenance = (*maintenanceSwitch)(nil)

// Enter switches maintenance on for reason. It fails with fault.Busy
// while another reason holds it.
func (m *maintenanceSwitch) Enter(_ context.Context, reason backup.MaintenanceReason) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.on {
		return nil, fault.New(fault.Busy, "")
	}
	m.on, m.reason = true, reason
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.reason == reason && reason != backup.MaintenanceSourceChange {
				m.on, m.reason = false, ""
			}
		})
	}, nil
}

// Active reports the reason while maintenance is on.
func (m *maintenanceSwitch) Active() (backup.MaintenanceReason, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reason, m.on
}

// Load reports whether maintenance is on (readiness and the gates of the
// areas).
func (m *maintenanceSwitch) Load() bool {
	_, on := m.Active()
	return on
}

// forceSourceChange switches to legacy_source_changed even while another
// reason holds maintenance: the legacy data changed, and only a restart
// may end that.
func (m *maintenanceSwitch) forceSourceChange() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.on, m.reason = true, backup.MaintenanceSourceChange
}
