package hostops

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Limits of the reachability check (overview_routes.py).
const (
	MaxProbes            = 50
	probeTimeout         = 3 * time.Second
	greetingTimeout      = time.Second
	greetingLimit        = 1024
	checkDeadline        = 8 * time.Second
	cacheFresh           = 60 * time.Second
	resultRetention      = 30 * time.Minute
	maxConcurrentChecks  = 3
	maxConcurrentProbes  = 8
	checkRateLimit       = 6
	probeBudget          = 150
	reachabilityRateSpan = time.Minute
)

// ReachHost is a saved host with the endpoint its first hop has: the jump
// host for a host behind one, the SOCKS5 proxy for a host behind one, the
// host itself otherwise. Endpoint is empty where that record is missing.
type ReachHost struct {
	ID           string
	AuthType     string
	JumpHostID   string
	SOCKSProxyID string
	// Host and Port are the first hop as stored (Port 0: the default 22);
	// Missing is set when the jump host or proxy no longer exists.
	// Username is the remote user of a direct Tailscale SSH host.
	Host     string
	Port     int
	Username string
	Missing  bool
}

// ReachInventory lists the saved hosts of an account in list order.
type ReachInventory func(ctx context.Context, owner int64) ([]ReachHost, error)

// ProbeTarget is one endpoint of the check.
type ProbeTarget struct {
	Host string // canonical
	Port int
	// Tailnet marks a direct Tailscale SSH host that the caller may
	// launch (TailnetProber.MayLaunch); the check reaches it the way the
	// terminal does. User is its remote user.
	Tailnet bool
	User    string
	// SOCKS marks a SOCKS5 proxy: it sends no greeting, so the connection
	// alone answers.
	SOCKS bool
}

// TCPProber connects to an endpoint under the network policy (role
// probe). A refusal of the policy is a *fault.Error with TargetBlocked,
// TailnetRouteRestricted or InvalidValue, a name that does not resolve one
// with Unreachable; any other error is a target that did not answer.
type TCPProber interface {
	DialProbe(ctx context.Context, host string, port int) (Conn, error)
}

// TailnetProber reaches a direct Tailscale SSH host the way a terminal
// connection does (internal/ssh/tailscale through cmd/webssh). MayLaunch
// is profile_is_authorized_for_launch: the switch and the allowlists of
// users, targets and remote users, without any lookup. DialTailnet
// authorizes the exact connection (tailscale.Policy.Authorize: an address
// of the target whose kernel route leaves through the tailnet interface)
// and connects to that address bound to the interface; authorized is
// false when the target has no such route, and the check then probes it
// as any other host, under the network policy.
type TailnetProber interface {
	MayLaunch(p principal.Principal, host string, port int, remoteUser string) bool
	DialTailnet(ctx context.Context, p principal.Principal, host string, port int, remoteUser string) (conn Conn, authorized bool, err error)
}

// Conn is a probe connection.
type Conn = interface {
	Read(p []byte) (int, error)
	Close() error
	SetReadDeadline(t time.Time) error
}

// GreetingStore keeps the platform hints that the greetings of saved
// direct hosts named (internal/hosts CacheGreetingPlatforms).
type GreetingStore interface {
	CacheGreetingPlatforms(ctx context.Context, owner int64, observed map[string]Greeting) (int, error)
}

// Greeting is one hint for GreetingStore: the endpoint probed and the
// platform its greeting named ("" for none).
type Greeting struct {
	Host     string
	Port     int
	Platform string
}

type plan struct {
	target   ProbeTarget
	valid    bool
	viaJump  bool
	viaSOCKS bool
	socksID  string
}

// Outcome is the answer for one saved host.
type Outcome struct {
	State     string `json:"state"` // reachable, unreachable, blocked, unresolved, unchecked
	LatencyMS *int64 `json:"latency_ms,omitzero"`
	ViaJump   bool   `json:"via_jump,omitzero"`
	ViaSOCKS  bool   `json:"via_socks,omitzero"`
	platform  string
	greeted   bool
}

type cached struct {
	at        time.Time
	signature string
	results   map[string]Outcome
	checkedAt float64
}

// Reachability is the overview's bounded reachability check: a plain TCP
// connection to the first hop of each saved host, under the same network
// policy as a real connection, and the SSH identification line the server
// sends on its own. Nothing is sent and no credential is used. Unlike the
// Python release only an endpoint that identifies as an SSH server counts
// as reachable (D-27), so the check cannot serve as a port scanner; a
// saved SOCKS5 proxy, which sends no greeting, counts once it accepts the
// connection.
type Reachability struct {
	Inventory ReachInventory
	Prober    TCPProber
	Canonical func(host string) (string, error)
	// BlockInternal is BLOCK_INTERNAL_SSH: where internal targets are
	// blocked, "does not resolve" and "resolves to a blocked address" look
	// the same, so names cannot be probed for existence.
	BlockInternal bool
	Greetings     GreetingStore
	// Tailnet reaches direct Tailscale SSH hosts; nil: they are probed as
	// any other host, so a tailnet node reads as blocked while the route
	// restriction holds.
	Tailnet  TailnetProber
	now      func() time.Time
	deadline time.Duration

	mu         sync.Mutex
	generation uint64
	cache      map[int64]cached
	inFlight   map[int64]bool
	probes     chan struct{}
	once       sync.Once
}

func (r *Reachability) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// plans is _plans: one plan per saved host (wanted only, if given), at
// most MaxProbes, and the signature of exactly this set of destinations.
func (r *Reachability) plans(p principal.Principal, hosts []ReachHost, wanted map[string]bool) (map[string]plan, string) {
	plans := map[string]plan{}
	caller := p
	for _, h := range hosts {
		if wanted != nil && !wanted[h.ID] {
			continue
		}
		if len(plans) >= MaxProbes {
			break
		}
		p := plan{viaJump: h.JumpHostID != "", viaSOCKS: h.SOCKSProxyID != "", socksID: h.SOCKSProxyID}
		usable := !h.Missing && !(h.SOCKSProxyID != "" && (h.JumpHostID != "" || h.AuthType == "tailscale"))
		if usable {
			if host, err := r.Canonical(h.Host); err == nil {
				port := h.Port
				if port == 0 {
					port = 22
				}
				p.target, p.valid = ProbeTarget{Host: host, Port: port}, true
				p.target.SOCKS = p.viaSOCKS
				if h.AuthType == "tailscale" && !p.viaJump && !p.viaSOCKS && r.Tailnet != nil &&
					r.Tailnet.MayLaunch(caller, h.Host, port, h.Username) {
					p.target.Tailnet, p.target.User = true, h.Username
				}
			}
		}
		plans[h.ID] = p
	}
	keys := make([]string, 0, len(plans))
	for id, p := range plans {
		endpoint := "None"
		if p.valid {
			endpoint = p.target.Host + "|" + strconv.Itoa(p.target.Port)
		}
		keys = append(keys, strings.Join([]string{id, endpoint, strconv.FormatBool(p.viaJump), p.socksID,
			strconv.FormatBool(p.target.Tailnet)}, "\x00"))
	}
	slices.Sort(keys)
	return plans, strings.Join(keys, "\x01")
}

// Clear drops every stored answer after a change of the network policy
// (clear_reachability_cache of app/overview_routes.py); a check that is
// still running does not store its answer.
func (r *Reachability) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.cache)
	r.generation++
}

// Last returns the last check for the current hosts without contacting
// any host, or nil results.
func (r *Reachability) Last(ctx context.Context, p principal.Principal) (map[string]any, error) {
	hosts, err := r.Inventory(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	_, signature := r.plans(p, hosts, nil)
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.cache[p.UserID]
	if ok && c.signature == signature && r.clock().Sub(c.at) < resultRetention {
		return map[string]any{"results": c.results, "checked_at": c.checkedAt}, nil
	}
	return map[string]any{"results": nil}, nil
}

// probe is _probe: one TCP connection, the greeting read, nothing sent.
func (r *Reachability) probe(ctx context.Context, p principal.Principal, t ProbeTarget) Outcome {
	started := time.Now()
	dctx, cancel := context.WithTimeout(ctx, probeTimeout)
	conn, tailnet, err := r.dial(dctx, p, t)
	cancel()
	if err != nil && tailnet {
		// The authorized tailnet connection did not answer.
		return Outcome{State: "unreachable"}
	}
	if err != nil {
		switch code := fault.CodeOf(err); {
		case code == fault.Unreachable && !r.BlockInternal:
			return Outcome{State: "unresolved"}
		case code == fault.Unreachable || refusedByPolicy(err):
			return Outcome{State: "blocked"}
		}
		return Outcome{State: "unreachable"}
	}
	latency := time.Since(started).Milliseconds()
	if t.SOCKS {
		_ = conn.Close()
		return Outcome{State: "reachable", LatencyMS: &latency}
	}
	data := readGreeting(ctx, conn, greetingLimit, greetingTimeout, func(b []byte) bool { return identificationLine(b) != nil })
	line := identificationLine(data)
	if line == nil {
		return Outcome{State: "unreachable"}
	}
	b, ok := DescribeBanner(line)
	if !ok {
		return Outcome{State: "unreachable"}
	}
	return Outcome{State: "reachable", LatencyMS: &latency, platform: b.Platform, greeted: true}
}

// dial connects to t: a launchable Tailscale SSH host over its authorized
// tailnet route (tailnet true), anything else under the network policy.
func (r *Reachability) dial(ctx context.Context, p principal.Principal, t ProbeTarget) (Conn, bool, error) {
	if t.Tailnet && r.Tailnet != nil {
		conn, authorized, err := r.Tailnet.DialTailnet(ctx, p, t.Host, t.Port, t.User)
		if authorized {
			return conn, true, err
		}
	}
	conn, err := r.Prober.DialProbe(ctx, t.Host, t.Port)
	return conn, false, err
}

// identificationLine is the first complete line starting with "SSH-";
// other lines may precede it (RFC 4253, section 4.2).
func identificationLine(data []byte) []byte {
	lines := bytes.Split(data, []byte{'\n'})
	for _, l := range lines[:len(lines)-1] {
		if bytes.HasPrefix(l, []byte("SSH-")) {
			return l
		}
	}
	return nil
}
