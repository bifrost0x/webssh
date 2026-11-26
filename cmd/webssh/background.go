package main

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/migrate/legacy"
)

const (
	// sweepInterval is how often expired sessions are removed and their
	// end published; validation refuses them on its own in between.
	sweepInterval = 5 * time.Minute
	// sourceWatchInterval is the re-check of the legacy source while Go
	// serves (migration specification, section 5.7).
	sourceWatchInterval = 60 * time.Second
	// revocationFollowInterval is how often revocations committed by
	// another process (an administrator command such as reset-password)
	// are picked up; they then take effect like those of this process.
	revocationFollowInterval = time.Second
)

// startBackground runs the periodic work of the server until close.
func (s *system) startBackground(ctx context.Context) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.stopBackground = cancel
	s.background.Go(func() { s.every(ctx, sweepInterval, s.sweepSessions) })
	s.background.Go(func() { s.every(ctx, revocationFollowInterval, s.followRevocations) })
	watch, err := legacy.NewSourceWatch(ctx, s.db, s.cfg.DataDir)
	switch {
	case err != nil:
		s.sourceChanged(ctx, err)
	case watch != nil:
		s.background.Go(func() {
			s.every(ctx, sourceWatchInterval, func(ctx context.Context) bool {
				changed, err := watch.Changed()
				if changed || err != nil {
					s.sourceChanged(ctx, err)
					return false
				}
				return true
			})
		})
	}
}

// every calls fn every interval until ctx ends or fn returns false.
func (s *system) every(ctx context.Context, interval time.Duration, fn func(context.Context) bool) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !fn(ctx) {
				return
			}
		}
	}
}

func (s *system) followRevocations(ctx context.Context) bool {
	if n, err := s.sessions.FollowRevocations(ctx); err != nil {
		s.log.Warn("revocations of other processes not read", "err", err)
	} else if n > 0 {
		s.log.Info("sessions ended by another process", "count", n)
	}
	return true
}

func (s *system) sweepSessions(ctx context.Context) bool {
	if n, err := s.sessions.Sweep(ctx); err != nil {
		s.log.Warn("session sweep failed", "err", err)
	} else if n > 0 {
		s.log.Info("expired sessions removed", "count", n)
	}
	return true
}

// sourceChanged switches to maintenance: the legacy data changed under a
// running server, typically because the Python release runs on the same
// data directory again. Go stops serving the data until an administrator
// resolves it; an unreadable source counts as a change (fail closed).
func (s *system) sourceChanged(ctx context.Context, cause error) {
	if !s.maintenance.CompareAndSwap(false, true) {
		return
	}
	msg := "the legacy data changed while WebSSH runs; it now answers only the health checks. " +
		"Stop the other process that uses this data directory, then restart; `webssh migrate --replace` migrates the current legacy data"
	if cause != nil {
		s.log.Error("legacy source unreadable; maintenance", "err", cause, "action", msg)
	} else {
		s.log.Error("legacy source changed; maintenance", "action", msg)
	}
	s.audit.SecurityWarning("LEGACY_SOURCE_CHANGED", "unreadable", cause != nil)
	if s.realtime != nil {
		s.background.Go(func() {
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := s.realtime.Shutdown(sctx); err != nil {
				s.log.Warn("realtime connections not closed for maintenance", "err", err)
			}
		})
	}
}
