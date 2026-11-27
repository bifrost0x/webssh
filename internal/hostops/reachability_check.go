package hostops

import (
	"context"
	"log/slog"
	"sync"

	"github.com/bifrost0x/webssh/internal/principal"
)

// run checks the hosts of owner; allow charges the rate limits once the
// check is not answered from the cache.
func (c *Reachability) run(ctx context.Context, p principal.Principal, wanted map[string]bool, allow func(endpoints int) bool, log *slog.Logger) (map[string]any, error) {
	owner := p.UserID
	hosts, err := c.Inventory(ctx, owner)
	if err != nil {
		return nil, err
	}
	plans, signature := c.plans(p, hosts, wanted)
	targets := map[ProbeTarget]bool{}
	for _, p := range plans {
		if p.valid {
			targets[p.target] = true
		}
	}
	c.mu.Lock()
	if cc, ok := c.cache[owner]; ok && cc.signature == signature && c.clock().Sub(cc.at) < cacheFresh {
		c.mu.Unlock()
		return map[string]any{"results": cc.results, "cached": true, "checked_at": cc.checkedAt}, nil
	}
	c.mu.Unlock()
	if !allow(len(targets)) {
		return nil, errCheckRate
	}
	c.mu.Lock()
	switch {
	case c.inFlight[owner]:
		c.mu.Unlock()
		return nil, errCheckRunning
	case len(c.inFlight) >= maxConcurrentChecks:
		c.mu.Unlock()
		return nil, errChecksBusy
	}
	if c.inFlight == nil {
		c.inFlight, c.cache = map[int64]bool{}, map[int64]cached{}
	}
	c.inFlight[owner] = true
	generation := c.generation
	c.mu.Unlock()
	outcomes := c.probeAll(ctx, p, targets)
	c.mu.Lock()
	delete(c.inFlight, owner)
	c.mu.Unlock()

	results := map[string]Outcome{}
	greetings := map[string]Greeting{}
	for id, p := range plans {
		out := Outcome{State: "unresolved"}
		if p.valid {
			out = outcomes[p.target]
		}
		switch {
		case p.viaSOCKS:
			// The proxy's greeting never describes the SSH target.
			out.ViaSOCKS = true
		case p.viaJump:
			// The probe reached the jump host; its greeting says nothing
			// about the target.
			out.ViaJump = true
		case out.greeted:
			greetings[id] = Greeting{Host: p.target.Host, Port: p.target.Port, Platform: out.platform}
		}
		results[id] = out
	}
	updated := false
	if len(greetings) > 0 && c.Greetings != nil {
		n, err := c.Greetings.CacheGreetingPlatforms(context.WithoutCancel(ctx), owner, greetings)
		if err != nil && log != nil {
			// Platform hints are optional; the answer still stands.
			log.WarnContext(ctx, "platform hints from the reachability check were not stored", "user_id", owner, "error", err)
		}
		updated = n > 0
	}
	checkedAt := unix(c.clock())
	c.mu.Lock()
	// A policy change during the check makes its answer stale.
	if generation == c.generation {
		c.cache[owner] = cached{at: c.clock(), signature: signature, results: results, checkedAt: checkedAt}
	}
	c.mu.Unlock()
	if log != nil {
		log.InfoContext(ctx, "overview reachability check", "user_id", owner, "hosts", len(plans), "endpoints", len(targets))
	}
	return map[string]any{"results": results, "cached": false, "checked_at": checkedAt, "platforms_updated": updated}, nil
}

// probeAll probes the targets on the shared pool within the deadline of a
// check. A probe that did not answer in time, or never started, is
// "unchecked": unknown, not down.
func (c *Reachability) probeAll(ctx context.Context, p principal.Principal, targets map[ProbeTarget]bool) map[ProbeTarget]Outcome {
	c.once.Do(func() { c.probes = make(chan struct{}, maxConcurrentProbes) })
	deadline := c.deadline
	if deadline == 0 {
		deadline = checkDeadline
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deadline)
	defer cancel()
	var mu sync.Mutex
	out := make(map[ProbeTarget]Outcome, len(targets))
	var wg sync.WaitGroup
	for t := range targets {
		wg.Go(func() {
			select {
			case c.probes <- struct{}{}:
			case <-dctx.Done():
				return
			}
			defer func() { <-c.probes }()
			o := c.probe(dctx, p, t)
			if dctx.Err() != nil {
				return
			}
			mu.Lock()
			out[t] = o
			mu.Unlock()
		})
	}
	wg.Wait()
	for t := range targets {
		if _, ok := out[t]; !ok {
			out[t] = Outcome{State: "unchecked"}
		}
	}
	return out
}
