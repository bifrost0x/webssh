package automation

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// connectTimeout bounds the connection to one target, jump host included
// (the 15 s guard of the Python release).
const connectTimeout = 15 * time.Second

// runState is one run in its goroutine.
type runState struct {
	s      *Service
	j      job
	a      *active
	budget int

	mu        sync.Mutex
	lastCheck time.Time
	valid     bool
}

// check is the throttled part of cancelled(): the switch, the server,
// the saved passwords as bound at the review, and the schedule's grant.
func (rs *runState) check(ctx context.Context) bool {
	if err := rs.s.enabledSwitch(ctx); err != nil {
		return false
	}
	if rs.j.scheduled != nil && rs.j.scheduled.Check != nil && rs.j.scheduled.Check(ctx) != nil {
		return false
	}
	if rs.j.check != nil && rs.j.check(ctx) != nil {
		return false
	}
	if len(rs.j.frozen.Bindings) == 0 {
		return true
	}
	b, err := rs.s.bindings(ctx, rs.j.userID, rs.j.frozen.Targets, false)
	return err == nil && maps.Equal(b, rs.j.frozen.Bindings)
}

// cancelled reports whether the run must stop: cancelled, past its
// deadline, or its grant no longer holds (checked at most every 250 ms
// unless force).
func (rs *runState) cancelled(force bool) bool {
	if rs.a.isStopped() || rs.a.ctx.Err() != nil {
		return true
	}
	rs.mu.Lock()
	due := force || rs.lastCheck.IsZero() || time.Since(rs.lastCheck) > recheckEvery
	if due {
		rs.lastCheck = time.Now()
	}
	valid := rs.valid
	rs.mu.Unlock()
	if due {
		valid = rs.check(rs.a.ctx)
		rs.mu.Lock()
		rs.valid = valid
		rs.mu.Unlock()
	}
	return !valid
}

// watch cancels ctx when the run must stop while a step or a connection
// attempt waits.
func (rs *runState) watch(ctx context.Context) (context.Context, func()) {
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(recheckEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-wctx.Done():
				return
			case <-rs.a.stopped:
				cancel()
				return
			case <-t.C:
				if rs.cancelled(false) {
					cancel()
					return
				}
			}
		}
	}()
	return wctx, func() { close(done); cancel() }
}

func (rs *runState) persist() {
	if err := rs.s.persist(rs.a.ctx, rs.j.userID, rs.a.snapshot()); err != nil {
		rs.s.o.Logger.Warn("automation: run record not stored", "user_id", rs.j.userID, "error", err)
	}
}

// run is _work.
func (s *Service) run(j job, a *active, budget int) {
	rs := &runState{s: s, j: j, a: a, budget: budget, valid: true}
	defer func() {
		s.finish(rs)
		s.mu.Lock()
		delete(s.active, j.userID)
		s.mu.Unlock()
		a.cancel()
	}()
	a.update(func(r *Run) { r.Status = StatusRunning })
	if err := s.validate(a.ctx, j.userID, j.frozen); err != nil {
		rs.skipFrom(0, err)
		return
	}
	for i := range j.frozen.Targets {
		if rs.cancelled(true) {
			return
		}
		if !rs.target(i) && j.frozen.Runbook.StopOnError {
			return
		}
	}
}

// skipFrom records that nothing was sent to the targets from index i on,
// with the reason, instead of an ambiguous outcome.
func (rs *runState) skipFrom(i int, err error) {
	reason := Code(err)
	if !slices.Contains(connectionReasons, reason) {
		reason = "preview_changed"
	}
	rs.a.update(func(r *Run) {
		for k := i; k < len(r.Targets); k++ {
			r.Targets[k].Status = StatusSkipped
			r.Targets[k].Reason = new(reason)
		}
	})
}

// secret returns the saved password of a password hop.
func (rs *runState) secret(ctx context.Context, h *hop) ([]byte, error) {
	if h == nil || h.AuthType != "password" {
		return nil, nil
	}
	p, err := rs.s.o.Passwords.Password(ctx, rs.j.userID, h.ResourceID, h.Target)
	if err != nil {
		if c := faultCode(err); c == "credential_missing" {
			return nil, Fail(c)
		}
		return nil, Fail("preview_changed")
	}
	return p, nil
}

// target runs the steps on one host and reports whether it succeeded.
func (rs *runState) target(i int) bool {
	s, ctx, f := rs.s, rs.a.ctx, rs.j.frozen.Targets[i]
	if err := s.validate(ctx, rs.j.userID, rs.j.frozen); err != nil {
		rs.skipFrom(i, err)
		return false
	}
	password, err := rs.secret(ctx, &f.hop)
	if err != nil {
		rs.skipFrom(i, err)
		return false
	}
	defer clear(password)
	routePassword, err := rs.secret(ctx, f.Route)
	if err != nil {
		rs.skipFrom(i, err)
		return false
	}
	defer clear(routePassword)
	rs.a.update(func(r *Run) { r.Targets[i].Status = StatusRunning })
	rs.persist()
	var secrets []string
	for _, p := range [][]byte{password, routePassword} {
		if len(p) > 0 {
			secrets = append(secrets, string(p))
		}
	}
	conn, err := rs.connect(f, string(password), string(routePassword))
	if err == nil {
		rs.steps(i, f, conn, secrets)
		_ = conn.Close()
	}
	rs.a.update(func(r *Run) { settleTarget(&r.Targets[i], err, rs.cancelled(false)) })
	rs.persist()
	return rs.a.snapshot().Targets[i].Status == StatusSucceeded
}

// settleTarget sets the outcome of a target after its steps or a
// failed connection; queued steps were skipped.
func settleTarget(t *Target, connErr error, cancelled bool) {
	open := false
	for _, st := range t.Steps {
		open = open || st.Status == StatusUnknown || st.Status == StatusRunning
	}
	if connErr != nil {
		switch {
		case open:
			t.Reason, t.Status = new("run_interrupted"), StatusUnknown
		case cancelled:
			t.Reason, t.Status = new(connectionReason(connErr)), StatusCancelled
		default:
			t.Reason, t.Status = new(connectionReason(connErr)), StatusFailed
		}
	} else {
		all, failed := true, false
		for _, st := range t.Steps {
			all = all && st.Status == StatusSucceeded
			failed = failed || st.Status == StatusFailed
		}
		switch {
		case open:
			t.Status = StatusUnknown
		case all:
			t.Status = StatusSucceeded
		case failed:
			t.Status = StatusFailed
		default:
			t.Status = StatusCancelled
		}
	}
	for k := range t.Steps {
		if t.Steps[k].Status == StatusQueued {
			t.Steps[k].Status = StatusSkipped
		}
	}
}

// connectionReason is connection_reason for the errors of the dialer.
func connectionReason(err error) string {
	if c := Code(err); slices.Contains(connectionReasons, c) {
		return c
	}
	switch {
	case fault.Is(err, fault.HostKeyNotAccepted):
		return "host_key_required"
	case fault.Is(err, fault.HostKeyRevoked):
		return "host_key_revoked"
	case fault.Is(err, fault.HostKeyChanged):
		return "host_key_changed"
	case fault.Is(err, fault.AuthFailed):
		return "authentication_failed"
	case fault.Is(err, fault.Timeout), errors.Is(err, context.DeadlineExceeded):
		return "connect_timeout"
	case fault.Is(err, fault.TailnetRouteRestricted):
		return "tailscale_route_restricted"
	}
	return "connection_failed"
}

// steps runs the runbook on an open connection.
func (rs *runState) steps(i int, f Frozen, conn Conn, secrets []string) {
	login := Login{Host: f.Host, Port: int(f.Port), User: f.Username, JumpHostID: f.JumpHostID}
	for k, step := range rs.j.frozen.Runbook.Steps {
		if rs.cancelled(true) {
			return
		}
		rs.a.update(func(r *Run) { r.Targets[i].Steps[k].Status = StatusRunning })
		rs.persist()
		sctx, done := rs.watch(rs.a.ctx)
		res := runStep(sctx, conn, step, func() bool { return rs.cancelled(false) }, secrets, rs.budget, rs.s.o.Now)
		done()
		rs.budget -= len(res.Stdout) + len(res.Stderr)
		rs.a.update(func(r *Run) {
			res.order, res.Name = r.Targets[i].Steps[k].order, r.Targets[i].Steps[k].Name
			r.Targets[i].Steps[k] = res
		})
		if rs.s.o.Facts != nil {
			_ = rs.s.o.Facts.StepFinished(rs.a.ctx, rs.j.userID, f.ResourceID, login, step, res)
		}
		if res.Status != StatusSucceeded {
			return
		}
	}
}

// connect opens the connection of a target through its jump host with
// the reviewed sign-in of each hop. The saved host must still resolve to
// the reviewed endpoint.
func (rs *runState) connect(f Frozen, password, routePassword string) (Conn, error) {
	s := rs.s
	ctx, done := rs.watch(rs.a.ctx)
	defer done()
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	t, err := s.o.Resolver.Resolve(ctx, rs.j.userID, f.ResourceID)
	if err != nil {
		return nil, Fail("preview_changed")
	}
	if t.Proxy != nil || t.Variant != nil || len(t.Jumps) > 1 || (len(t.Jumps) == 1) != (f.Route != nil) ||
		!sameHop(t.Hop, &f.hop) || (f.Route != nil && !sameHop(t.Jumps[0], f.Route)) {
		return nil, Fail("preview_changed")
	}
	guard := &bindingGuard{rs: rs}
	t.Hop.Auth = rs.auth(&f.hop, password, guard)
	if f.Route != nil {
		t.Jumps[0].Auth = rs.auth(f.Route, routePassword, guard)
	}
	if rs.cancelled(true) {
		return nil, Fail("cancelled")
	}
	release, err := s.o.Quotas.Reserve(ctx, "ssh_session", rs.j.userID, 1)
	if err != nil {
		return nil, err
	}
	conn, err := s.o.Dialer.Dial(ctx, t, Unattended{})
	if err != nil {
		release()
		return nil, err
	}
	return &releasing{Conn: conn, release: release}, nil
}

// releasing gives the session quota back when the connection closes.
type releasing struct {
	Conn
	release func()
	once    sync.Once
}

func (r *releasing) Close() error {
	err := r.Conn.Close()
	r.once.Do(r.release)
	return err
}

func sameHop(h client.Hop, f *hop) bool {
	return h.Port == int(f.Port) && h.User == f.Username && h.Host == f.Host
}

func (rs *runState) auth(h *hop, password string, guard client.PasswordGuard) client.Auth {
	if h.AuthType == "key" {
		return client.Auth{KeyID: h.KeyID}
	}
	return client.Auth{Password: password, Guard: guard}
}

// bindingGuard re-checks the review right before a saved password is
// sent: a host-key or banner wait may outlive the assignment.
type bindingGuard struct{ rs *runState }

func (g *bindingGuard) Check(ctx context.Context) error {
	if g.rs.cancelled(true) {
		return Fail("cancelled")
	}
	return g.rs.s.validate(ctx, g.rs.j.userID, g.rs.j.frozen)
}

// Unattended is the interaction of a run: a host key without trust is
// refused, a pre-authentication banner is accepted without a prompt, as
// the automation of the Python release never asked.
type Unattended struct{}

// HostKey refuses: automation never trusts on first use.
func (Unattended) HostKey(context.Context, client.HostKeyPrompt) (bool, error) { return false, nil }

// Banner accepts the banner.
func (Unattended) Banner(context.Context, client.BannerPrompt) (bool, error) { return true, nil }
