package main

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/tailscale"
)

// discoveryArea wires the area "discovery" (HO2): discovery, platform facts and the overview (internal/hostops, internal/hosts).
// HO2 fills in the hooks; no other package edits this file.
func discoveryArea() extension {
	w := &discoveryWiring{}
	return extension{name: "discovery", prepare: w.prepare, wire: w.wire}
}

// discoveryWiring holds the parts of the area. prepare runs before the
// capabilities exist, so it hands out values whose collaborators wire
// fills in; nothing serves before wire has run.
type discoveryWiring struct {
	sys      *system
	scanner  *hostops.Scanner
	reach    *hostops.Reachability
	detector *hosts.Detector
	ctx      context.Context
}

func (w *discoveryWiring) prepare(sys *system) error {
	w.sys = sys
	w.scanner = &hostops.Scanner{Resolver: net.DefaultResolver, Audit: sys.audit, Log: sys.log}
	w.reach = &hostops.Reachability{Canonical: netpolicy.CanonicalHost, BlockInternal: sys.cfg.Network.BlockInternalSSH}
	w.detector = &hosts.Detector{Describe: describePlatform, Log: sys.log}
	ctx, cancel := context.WithCancel(context.Background())
	w.ctx = ctx
	sys.optional.reachability = w.reach
	sys.optional.discoveryAvailable = w.discoveryAvailable
	sys.optional.connectionObserver = func(t client.Target, c *client.Conn) { w.detector.Connected(w.ctx, t, c) }
	sys.closers = append(sys.closers, func() error {
		cancel()
		sctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		return errors.Join(w.scanner.Shutdown(sctx), w.detector.Shutdown(sctx))
	})
	return nil
}

func (w *discoveryWiring) wire(sys *system) error {
	prober := probeDialer{policy: sys.policy}
	limiter := userLimiter{l: sys.limiter}
	accepting := func() bool { return !sys.maintenance.Load() }
	w.scanner.Dialer = prober
	w.reach.Prober = prober
	w.reach.Inventory = reachInventory{sys.hosts}.list
	w.reach.Greetings = greetingStore{sys.hosts}
	if v, ok := sys.optional.terminalVariants.(*variantProvider); ok && v.policy.Enabled() {
		w.reach.Tailnet = tailnetProbe{v.policy}
	}
	w.detector.Hosts = sys.hosts
	w.detector.Notify = func(owner int64, typ string, payload any) { sys.realtime.NotifyUser(owner, typ, payload) }
	(&hostops.DiscoveryHTTP{Scanner: w.scanner, Enabled: sys.cfg.Features.HostDiscovery,
		Permitted: w.permitted(settings.PolicyDiscovery), Known: knownEndpoints{sys.hosts}.endpoints,
		Limiter: limiter, Accepting: accepting, Logger: sys.log}).Register(sys.edge.Mux())
	(&hostops.ReachabilityHTTP{Check: w.reach, Permitted: w.permitted(settings.PolicyReachability),
		Limiter: limiter, Accepting: accepting, Logger: sys.log}).Register(sys.edge.Mux())
	unsubscribe := sys.sessions.Subscribe(w.scanner.Revoked)
	sys.closers = append(sys.closers, func() error { unsubscribe(); return nil })
	return nil
}

// permitted reads one permission of the derived settings (A13): granted
// to the administrators always, to other roles as the setting says.
func (w *discoveryWiring) permitted(key string) hostops.Permission {
	return func(ctx context.Context, p principal.Principal) (bool, error) {
		app, err := w.sys.settings.App(ctx)
		if err != nil {
			return false, err
		}
		roles := app.Policy.Discovery
		if key == settings.PolicyReachability {
			roles = app.Policy.Reachability
		}
		return settings.Granted(roles, settings.RoleUser, p.IsAdmin), nil
	}
}

// discoveryAvailable is host_discovery_available: HOST_DISCOVERY_ENABLED
// and the account's permission.
func (w *discoveryWiring) discoveryAvailable(ctx context.Context, p principal.Principal) bool {
	if !w.sys.cfg.Features.HostDiscovery {
		return false
	}
	ok, err := w.permitted(settings.PolicyDiscovery)(ctx, p)
	return err == nil && ok
}

func describePlatform(line []byte) (string, bool) {
	b, ok := hostops.DescribeBanner(line)
	return b.Platform, ok
}

// probeDialer dials discovery and reachability probes under the network
// policy with the role probe.
type probeDialer struct{ policy *netpolicy.Policy }

func (d probeDialer) DialProbe(ctx context.Context, host string, port int) (hostops.Conn, error) {
	return d.policy.DialContext(ctx, netpolicy.RoleProbe, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// tailnetProbe reaches direct Tailscale SSH hosts for the reachability
// check with the policy of the terminal connection (wire_gateway.go): the
// same authorization, the pinned address and the tailnet interface.
var _ hostops.TailnetProber = tailnetProbe{}

type tailnetProbe struct{ policy *tailscale.Policy }

func (t tailnetProbe) MayLaunch(p principal.Principal, host string, port int, remoteUser string) bool {
	return t.policy.Check(tsUser(p), host, port, remoteUser) == nil
}

func (t tailnetProbe) DialTailnet(ctx context.Context, p principal.Principal, host string, port int, remoteUser string) (hostops.Conn, bool, error) {
	auth, err := t.policy.Authorize(ctx, tsUser(p), host, port, remoteUser)
	if err != nil {
		return nil, false, nil
	}
	conn, err := netpolicy.DialInterface(ctx, auth.Interface(), auth.Addr())
	if err != nil {
		return nil, true, err
	}
	return conn, true, nil
}

// userLimiter adapts the in-process limiter to the per-account limits of
// the area (check_user_rate_limit). They apply whether or not
// RATELIMIT_ENABLED is set, as in the Python release.
type userLimiter struct{ l *auth.Limiter }

func (u userLimiter) Allow(key string, limit int, window time.Duration) bool {
	ok, _ := u.l.Allow(key, auth.Rule{Limit: limit, Window: window})
	return ok
}

// knownEndpoints lists the saved endpoints of an account for the "Saved"
// mark of discovery results (_known_endpoints).
type knownEndpoints struct{ hosts *hosts.Service }

func (k knownEndpoints) endpoints(ctx context.Context, owner int64) (map[string]bool, error) {
	out := map[string]bool{}
	lists := []func(context.Context, int64) ([]jsontext.Value, error){k.hosts.Profiles, k.hosts.JumpHosts, k.hosts.SOCKSProxies}
	for _, list := range lists {
		records, err := list(ctx, owner)
		if err != nil {
			return nil, err
		}
		for _, raw := range records {
			r, err := decodeRecord(raw)
			if err != nil {
				return nil, err
			}
			port := recordPort(r.Port)
			if port == 0 {
				port = 22
			}
			out[strings.ToLower(r.Host)+"|"+strconv.Itoa(port)] = true
		}
	}
	return out, nil
}

// reachInventory adapts the saved hosts to hostops.ReachInventory: every
// host with the endpoint of its first hop.
type reachInventory struct{ hosts *hosts.Service }

func (ri reachInventory) list(ctx context.Context, owner int64) ([]hostops.ReachHost, error) {
	index := func(list func(context.Context, int64) ([]jsontext.Value, error)) (map[string]overviewRecord, error) {
		records, err := list(ctx, owner)
		if err != nil {
			return nil, err
		}
		out := map[string]overviewRecord{}
		for _, raw := range records {
			r, err := decodeRecord(raw)
			if err != nil {
				return nil, err
			}
			out[r.ID] = r
		}
		return out, nil
	}
	jumps, err := index(ri.hosts.JumpHosts)
	if err != nil {
		return nil, err
	}
	proxies, err := index(ri.hosts.SOCKSProxies)
	if err != nil {
		return nil, err
	}
	profiles, err := ri.hosts.Profiles(ctx, owner)
	if err != nil {
		return nil, err
	}
	out := make([]hostops.ReachHost, 0, len(profiles))
	for _, raw := range profiles {
		r, err := decodeRecord(raw)
		if err != nil {
			return nil, err
		}
		h := hostops.ReachHost{ID: r.ID, AuthType: r.AuthType, JumpHostID: deref(r.JumpHostID),
			SOCKSProxyID: deref(r.SOCKSProxyID), Host: r.Host, Port: recordPort(r.Port), Username: r.Username}
		first, ok := r, true
		if h.JumpHostID != "" {
			first, ok = jumps[h.JumpHostID]
		}
		if h.SOCKSProxyID != "" {
			first, ok = proxies[h.SOCKSProxyID]
		}
		h.Host, h.Port, h.Missing = first.Host, recordPort(first.Port), !ok
		out = append(out, h)
	}
	return out, nil
}

// greetingStore adapts internal/hosts to hostops.GreetingStore.
type greetingStore struct{ hosts *hosts.Service }

func (g greetingStore) CacheGreetingPlatforms(ctx context.Context, owner int64, observed map[string]hostops.Greeting) (int, error) {
	in := make(map[string]hosts.Greeting, len(observed))
	for id, v := range observed {
		in[id] = hosts.Greeting{Host: v.Host, Port: v.Port, Platform: v.Platform}
	}
	return g.hosts.CacheGreetingPlatforms(ctx, owner, in)
}
