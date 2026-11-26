package client

import (
	"net"
	"sync"
	"time"
)

// watchdog closes conn when the non-interactive part of a handshake takes
// longer than budget. Time spent waiting for the user (host-key decision,
// prompts) is paused; that wait is bounded by the hop context instead.
type watchdog struct {
	mu        sync.Mutex
	conn      net.Conn
	remaining time.Duration
	started   time.Time
	timer     *time.Timer
	fired     bool
	stopped   bool
}

func startWatchdog(conn net.Conn, budget time.Duration) *watchdog {
	w := &watchdog{conn: conn, remaining: budget}
	w.resumeLocked()
	return w
}

func (w *watchdog) resumeLocked() {
	if w.stopped || w.fired {
		return
	}
	w.started = time.Now()
	w.timer = time.AfterFunc(w.remaining, w.fire)
}

func (w *watchdog) fire() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	w.fired = true
	_ = w.conn.Close()
}

// pause stops the clock and returns the function that restarts it.
func (w *watchdog) pause() func() {
	w.mu.Lock()
	if w.timer != nil && w.timer.Stop() {
		w.remaining -= time.Since(w.started)
	}
	w.timer = nil
	w.mu.Unlock()
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.resumeLocked()
	}
}

// stop ends supervision and reports whether the budget ran out.
func (w *watchdog) stop() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
	if w.timer != nil {
		w.timer.Stop()
	}
	return w.fired
}
