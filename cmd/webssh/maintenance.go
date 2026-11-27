package main

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/fault"
)

// maintenance is the maintenance mode of the server (backup.Maintenance):
// while it is on, /ready answers 503, every other route answers 503
// maintenance (system.handler) and realtime connections are closed with
// 4503; new ones are refused by the handler. One reason holds it at a
// time. legacy_source_changed is never left: only a restart ends it, and
// it also takes over while another reason holds the mode.
type maintenance struct {
	on atomic.Bool

	mu     sync.Mutex
	reason backup.MaintenanceReason
	sticky bool
	// closeConns closes the open realtime connections; nil until the
	// realtime endpoint is wired.
	closeConns func(reason string) int
}

var _ backup.Maintenance = (*maintenance)(nil)

// Load reports whether the server is in maintenance; the HTTP handler and
// the readiness probe call it on every request.
func (m *maintenance) Load() bool { return m.on.Load() }

// Active implements backup.Maintenance.
func (m *maintenance) Active() (backup.MaintenanceReason, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reason, m.on.Load()
}

// Enter implements backup.Maintenance. legacy_source_changed must use
// enterPermanent; the reason is accepted here only when the mode is free,
// and then sticks as well.
func (m *maintenance) Enter(ctx context.Context, reason backup.MaintenanceReason) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validMaintenanceReason(reason) {
		return nil, fault.New(fault.InvalidValue, "")
	}
	m.mu.Lock()
	if m.on.Load() {
		m.mu.Unlock()
		return nil, fault.New(fault.Busy, "")
	}
	m.reason, m.sticky = reason, reason == backup.MaintenanceSourceChange
	m.on.Store(true)
	closeConns := m.closeConns
	m.mu.Unlock()
	if closeConns != nil {
		closeConns(string(reason))
	}
	var once sync.Once
	return func() { once.Do(func() { m.leave(reason) }) }, nil
}

// leave ends the mode if reason still holds it and it is not sticky.
func (m *maintenance) leave(reason backup.MaintenanceReason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sticky || m.reason != reason || !m.on.Load() {
		return
	}
	m.reason = ""
	m.on.Store(false)
}

// enterPermanent switches to maintenance for reason until the process
// ends, whatever reason held the mode before. It reports whether this
// call switched it (false when it already was permanent).
func (m *maintenance) enterPermanent(reason backup.MaintenanceReason) bool {
	m.mu.Lock()
	if m.sticky {
		m.mu.Unlock()
		return false
	}
	m.reason, m.sticky = reason, true
	m.on.Store(true)
	closeConns := m.closeConns
	m.mu.Unlock()
	if closeConns != nil {
		closeConns(string(reason))
	}
	return true
}

// setCloser connects the realtime endpoint once it is wired.
func (m *maintenance) setCloser(f func(reason string) int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeConns = f
}

func validMaintenanceReason(r backup.MaintenanceReason) bool {
	switch r {
	case backup.MaintenanceRestore, backup.MaintenanceRotation, backup.MaintenanceSourceChange:
		return true
	}
	return false
}
