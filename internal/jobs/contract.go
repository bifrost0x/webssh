package jobs

import (
	"context"
	"time"
)

// Func is the body of a job. It returns when ctx ends; its error is
// logged and shown in the job list, never sent to a browser.
type Func func(ctx context.Context) error

// Spec describes a registered job. Exactly one of Every and Cron is set
// for a periodic job; neither for a job that only runs on demand.
type Spec struct {
	// Every runs the job at this interval after the previous run ended.
	Every time.Duration
	// Cron runs the job at the times of a five-field expression in Zone
	// (internal/cron); Zone empty means UTC.
	Cron string
	Zone string
	// Singleton skips a due run while the previous one still runs. Runs of
	// non-singleton jobs are bounded by Concurrency.
	Singleton bool
	// Concurrency bounds parallel runs of one job (1 when zero).
	Concurrency int
	// Timeout ends one run (no bound when zero; the shutdown grace still
	// applies).
	Timeout time.Duration
	// Defer keeps the job running at shutdown until the shutdown callbacks
	// have finished (the deferred cancel of app/runtime_lifecycle.py),
	// for jobs that clean up connections.
	Defer bool
}

// State of a job in the list.
type State string

const (
	Idle      State = "idle"
	Running   State = "running"
	Cancelled State = "cancelled"
	Stopped   State = "stopped" // after shutdown
)

// Info is one job as the admin operations page lists it (C-AOPS-09).
type Info struct {
	Name     string
	State    State
	Runs     int // runs in progress
	LastRun  time.Time
	LastErr  bool // the last run ended with an error
	NextRun  time.Time
	Periodic bool
}

// Limits of the registry.
const (
	// DefaultShutdownGrace is RUNTIME_SHUTDOWN_GRACE_SECONDS (5, at most 30).
	DefaultShutdownGrace = 5 * time.Second
	MaxShutdownGrace     = 30 * time.Second
	// MaxPending bounds the on-demand runs waiting for a slot; RunNow
	// beyond it fails with fault.Busy. There is no unbounded queue.
	MaxPending = 64
)
