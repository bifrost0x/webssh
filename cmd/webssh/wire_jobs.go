package main

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/jobs"
	"github.com/bifrost0x/webssh/internal/quota"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// The quota policy is the one mechanism of the runtime quotas.
var _ terminal.Quotas = (*quota.Policy)(nil)

// jobsArea wires the area "jobs" (RT1): quotas, background jobs and cron (internal/quota, internal/jobs, internal/cron).
// RT1 fills in the hooks; no other package edits this file.
//
// The quota policy and the job registry are core services (buildRuntime,
// called by buildCore), so every area can reserve quotas and register
// jobs in its prepare or wire hook. The registry starts here, once
// everything is wired; jobs registered later are refused.
func jobsArea() extension {
	return extension{
		name:    "jobs",
		schemas: []store.Schema{jobs.Schema()},
		background: func(ctx context.Context, sys *system) {
			// Shutdown (drain, or close) ends the jobs with their grace;
			// the end of ctx would cancel them at once.
			sys.jobs.Start(context.WithoutCancel(ctx))
		},
	}
}

// buildRuntime creates the quota policy from QUOTA_* and the job
// registry with its durable state.
func (s *system) buildRuntime() error {
	limits := make(map[string]quota.Limit, len(s.cfg.Quotas))
	for kind, l := range s.cfg.Quotas {
		limits[kind] = quota.Limit{Global: l.Global, PerUser: l.PerUser}
	}
	var err error
	if s.quotas, err = quota.New(limits); err != nil {
		return fmt.Errorf("quotas: %w", err)
	}
	s.jobs = jobs.New(jobs.Options{Log: s.log, Grace: s.shutdownGrace(), Store: jobs.DBStore{DB: s.db}})
	s.closers = append(s.closers, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), jobs.MaxShutdownGrace)
		defer cancel()
		return s.jobs.Shutdown(ctx)
	})
	return nil
}
