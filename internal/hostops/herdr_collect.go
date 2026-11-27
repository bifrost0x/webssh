package hostops

import (
	"context"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Budgets of Herdr snapshots (app/herdr.py).
const (
	herdrTimeout         = 3 * time.Second
	herdrMinInterval     = 4 * time.Second
	herdrTimeoutInterval = 30 * time.Second
	herdrMaxConcurrent   = 4
	herdrMaxPerUser      = 2
)

// herdrState holds the per-session pacing and the process-wide and
// per-account budgets. Entries of a session live as long as it does.
type herdrState struct {
	mu       sync.Mutex
	running  int
	perUser  map[int64]int
	sessions map[string]*herdrSession
}

type herdrSession struct {
	busy      bool
	notBefore time.Time
	done      <-chan struct{}
}

// begin takes the session's turn and the budgets, or reports busy.
func (h *herdrState) begin(user int64, sessionID string, done <-chan struct{}, now time.Time) (end func(notBefore time.Time), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessions == nil {
		h.sessions, h.perUser = map[string]*herdrSession{}, map[int64]int{}
	}
	s := h.sessions[sessionID]
	if s == nil || s.done != done {
		s = &herdrSession{done: done}
		h.sessions[sessionID] = s
		go h.forget(sessionID, s)
	}
	if s.busy || now.Before(s.notBefore) || h.perUser[user] >= herdrMaxPerUser || h.running >= herdrMaxConcurrent {
		return nil, false
	}
	s.busy, s.notBefore = true, now.Add(herdrMinInterval)
	h.perUser[user]++
	h.running++
	return func(notBefore time.Time) {
		h.mu.Lock()
		defer h.mu.Unlock()
		s.busy = false
		if notBefore.After(s.notBefore) {
			s.notBefore = notBefore
		}
		h.running--
		if h.perUser[user]--; h.perUser[user] <= 0 {
			delete(h.perUser, user)
		}
	}, true
}

// forget drops the pacing of a session once it ends.
func (h *herdrState) forget(id string, s *herdrSession) {
	if s.done == nil {
		return
	}
	<-s.done
	h.mu.Lock()
	if h.sessions[id] == s {
		delete(h.sessions, id)
	}
	h.mu.Unlock()
}

func herdrAnswer(agents []protocol.HerdrAgent, truncated bool, reason string) protocol.HerdrResult {
	out := protocol.HerdrResult{Success: agents != nil, Agents: agents, Truncated: agents != nil && truncated}
	if out.Agents == nil {
		out.Agents = []protocol.HerdrAgent{}
	}
	if reason != "" {
		out.Reason = &reason
	}
	return out
}

func (d *Diagnostics) handleHerdr(ctx context.Context, _ protocol.Peer, req protocol.HerdrSnapshot) (protocol.HerdrResult, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HerdrResult{}, err
	}
	if !validSampleID(req.SessionID) {
		return herdrAnswer(nil, false, "unavailable"), nil
	}
	if d.Switches == nil || !d.Switches.HerdrEnabled(ctx) {
		return herdrAnswer(nil, false, "disabled"), nil
	}
	// The panel polls every ten seconds per host; the budget leaves room
	// for every admitted socket without letting one account queue remote
	// commands.
	if !d.herdrRate.allow(p.UserID, d.clock()) {
		return herdrAnswer(nil, false, "busy"), nil
	}
	live, ok := d.Sessions.Live(p.UserID, req.SessionID)
	if !ok {
		return herdrAnswer(nil, false, "unavailable"), nil
	}
	agents, truncated, reason := d.collectHerdr(ctx, p.UserID, req.SessionID, live)
	return herdrAnswer(agents, truncated, reason), nil
}

// collectHerdr is collect_snapshot: the session's own Herdr server is
// asked, never started. The saved host may have lost the option since
// the session connected, so it is checked again.
func (d *Diagnostics) collectHerdr(ctx context.Context, user int64, sessionID string, live Live) ([]protocol.HerdrAgent, bool, string) {
	if !live.Herdr || !d.overviewAllowed(ctx, user, live.ProfileID) {
		return nil, false, "not_enabled"
	}
	end, ok := d.herdr.begin(user, sessionID, live.Done, d.clock())
	if !ok {
		return nil, false, "busy"
	}
	var notBefore time.Time
	defer func() { end(notBefore) }()
	if live.Exec == nil {
		return nil, false, "disconnected"
	}
	sctx, cancel := sessionContext(ctx, live.Done, nil)
	defer cancel()
	res, err := remotecmd.Run(sctx, live.Exec, remotecmd.Command{
		Line: herdrSnapshotCommand, Timeout: herdrTimeout, MaxOutput: herdrMaxSnapshot + 1, MaxStderr: herdrMaxError,
	})
	switch {
	case err == nil:
	case fault.Is(err, fault.Timeout):
		if res.Truncated {
			return nil, false, "invalid"
		}
		// A host that does not answer is asked again much less often.
		notBefore = d.clock().Add(herdrTimeoutInterval)
		return nil, false, "timeout"
	case closed(live.Done):
		return nil, false, "disconnected"
	default:
		d.log().Warn("Herdr snapshot failed", "error_type", errorType(err))
		return nil, false, "unavailable"
	}
	if res.Truncated {
		return nil, false, "invalid"
	}
	if res.ExitStatus != 0 {
		return nil, false, herdrFailure(res.ExitStatus, res.Stderr)
	}
	agents, truncated, err := parseHerdrSnapshot(res.Stdout)
	if err != nil {
		return nil, false, "invalid"
	}
	return agents, truncated, ""
}

// overviewAllowed is overview_allowed: the integration is on and the
// owner's saved host opts in.
func (d *Diagnostics) overviewAllowed(ctx context.Context, owner int64, profileID string) bool {
	return profileID != "" && d.Herdr != nil && d.Herdr.Overview(ctx, owner, profileID)
}

func errorType(err error) string {
	if c := fault.CodeOf(err); c != "" {
		return string(c)
	}
	return "error"
}
