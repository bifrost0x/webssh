package main

import (
	"context"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/jobs"
	"github.com/bifrost0x/webssh/internal/quota"
)

// The quota policy takes QUOTA_* and is the one the terminal uses; the
// job registry runs with its state in the store and stops at close.
func TestSystemWiresQuotasAndJobs(t *testing.T) {
	sys, _ := openTestSystem(t, map[string]string{"QUOTA_SSH_SESSION_GLOBAL": "3", "QUOTA_SSH_SESSION_PER_USER": "1"})
	if u := sys.quotas.Usage()[quota.SSHSession]; u.Global != 3 || u.PerUser != 1 {
		t.Fatalf("ssh_session limits %+v", u)
	}
	release, err := sys.quotas.Reserve(t.Context(), quota.SSHSession, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := sys.quotas.Reserve(t.Context(), quota.SSHSession, 7, 1); !fault.Is(err, fault.Busy) {
		t.Fatalf("second session of one user: %v", err)
	}
	if st := sys.terminal.Stats(); st.Reserved != 0 {
		t.Fatalf("terminal reports %d reserved", st.Reserved)
	}
	if err := sys.jobs.Register("late", jobs.Spec{}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("a job registered after the start")
	}
	stored, err := (jobs.DBStore{DB: sys.db}).Load(t.Context())
	if err != nil || len(stored) != 0 {
		t.Fatalf("job state %v, %v", stored, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := sys.drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sys.jobs.RunNow(t.Context(), "any"); !fault.Is(err, fault.NotFound) {
		t.Fatalf("RunNow after drain: %v", err)
	}
}
