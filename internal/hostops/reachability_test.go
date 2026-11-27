package hostops

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type fakeGreetings struct {
	seen map[string]Greeting
	err  error
}

func (g *fakeGreetings) CacheGreetingPlatforms(_ context.Context, _ int64, observed map[string]Greeting) (int, error) {
	g.seen = observed
	return len(observed), g.err
}

func canonicalLower(host string) (string, error) {
	if host == "" || strings.ContainsAny(host, " /") {
		return "", errors.New("invalid host")
	}
	return strings.ToLower(host), nil
}

func reachFixture(hosts []ReachHost, script map[string]string) (*ReachabilityHTTP, *fakeProber, *fakeGreetings) {
	prober := &fakeProber{script: script}
	greetings := &fakeGreetings{}
	check := &Reachability{Inventory: func(context.Context, int64) ([]ReachHost, error) { return hosts, nil },
		Prober: prober, Canonical: canonicalLower, Greetings: greetings}
	h := &ReachabilityHTTP{Check: check, Limiter: &fakeLimiter{},
		Permitted: func(_ context.Context, p principal.Principal) (bool, error) { return p.UserID == 1, nil }}
	return h, prober, greetings
}

func reachRequest(t *testing.T, h *ReachabilityHTTP, p principal.Principal, body string) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	h.Register(mux)
	return serveMux(t, mux, &p, "POST", "/api/overview/reachability", body)
}

func TestReachabilityOutcomes(t *testing.T) {
	hosts := []ReachHost{
		{ID: "ssh", Host: "Ubuntu.Lan", Port: 22, AuthType: "key"},
		{ID: "banner-after-text", Host: "motd", Port: 2222, AuthType: "password"},
		{ID: "web", Host: "web", Port: 80, AuthType: "password"},
		{ID: "silent", Host: "silent", Port: 22},
		{ID: "blocked", Host: "blocked", Port: 22},
		{ID: "unresolved", Host: "nowhere", Port: 22},
		{ID: "down", Host: "down", Port: 22},
		{ID: "via-jump", Host: "ubuntu.lan", Port: 22, JumpHostID: "j"},
		{ID: "via-socks", Host: "proxy", Port: 1080, SOCKSProxyID: "s"},
		{ID: "socks-and-jump", Host: "proxy", Port: 1080, SOCKSProxyID: "s", JumpHostID: "j"},
		{ID: "jump-missing", Host: "", JumpHostID: "gone", Missing: true},
		{ID: "invalid", Host: "bad host"},
		{ID: "default-port", Host: "ubuntu.lan"},
	}
	h, prober, greetings := reachFixture(hosts, map[string]string{
		"ubuntu.lan:22": "ssh:SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
		"motd:2222":     "ssh:Welcome\r\nSSH-2.0-OpenSSH_9.2p1 Debian-2\r\n",
		"web:80":        "text:HTTP/1.1 400 Bad Request\r\n\r\n",
		"silent:22":     "silent",
		"blocked:22":    "blocked",
		"nowhere:22":    "unresolved",
		"proxy:1080":    "text:\x05\x00",
	})
	h.Check.deadline = 3 * time.Second
	status, body := reachRequest(t, h, principaltest.User(1), "")
	if status != 200 || body["cached"] != false {
		t.Fatalf("check: %d %v", status, body)
	}
	results := body["results"].(map[string]any)
	state := func(id string) string { return results[id].(map[string]any)["state"].(string) }
	want := map[string]string{
		"ssh": "reachable", "banner-after-text": "reachable", "web": "unreachable", "silent": "unreachable",
		"blocked": "blocked", "unresolved": "unresolved", "down": "unreachable", "via-jump": "reachable",
		"via-socks": "reachable", "socks-and-jump": "unresolved", "jump-missing": "unresolved",
		"invalid": "unresolved", "default-port": "reachable",
	}
	for id, s := range want {
		if got := state(id); got != s {
			t.Errorf("%s: %s, want %s", id, got, s)
		}
	}
	if results["via-jump"].(map[string]any)["via_jump"] != true || results["via-socks"].(map[string]any)["via_socks"] != true {
		t.Errorf("route flags missing: %v %v", results["via-jump"], results["via-socks"])
	}
	if _, ok := results["ssh"].(map[string]any)["latency_ms"]; !ok {
		t.Error("no latency for a reachable host")
	}
	// Greetings are hints for direct hosts only; one probe per endpoint.
	if g := greetings.seen; len(g) != 3 || g["ssh"].Platform != "ubuntu" || g["banner-after-text"].Platform != "debian" {
		t.Errorf("greetings %+v", g)
	}
	if body["platforms_updated"] != true {
		t.Error("platforms_updated not reported")
	}
	if n := prober.written.Load(); n != 0 {
		t.Errorf("the check sent %d bytes", n)
	}
	dialed := len(prober.dials())

	// A second check within a minute is answered from the cache.
	if _, body := reachRequest(t, h, principaltest.User(1), `{"ids":null}`); body["cached"] != true {
		t.Errorf("not cached: %v", body)
	}
	if len(prober.dials()) != dialed {
		t.Error("the cached answer contacted hosts")
	}
	last, err := h.Check.Last(t.Context(), principaltest.User(1))
	if err != nil || last["results"] == nil {
		t.Errorf("last: %v %v", last, err)
	}
}

func TestReachabilityRefusals(t *testing.T) {
	h, _, _ := reachFixture([]ReachHost{{ID: "a", Host: "a", Port: 22}}, map[string]string{})
	if status, body := reachRequest(t, h, principaltest.User(2), ""); status != 403 || body["code"] != "forbidden" {
		t.Errorf("without permission: %d %v", status, body)
	}
	for _, body := range []string{`[1]`, `{"ids":"a"}`, `{"ids":[1]}`, `{"ids":["` + strings.Repeat("x", 129) + `"]}`} {
		if status, out := reachRequest(t, h, principaltest.User(1), body); status != 400 || out["code"] != "invalid_request" {
			t.Errorf("%s: %d %v", body, status, out)
		}
	}
	// Malformed JSON checks every host, as get_json(silent=True) did.
	if status, _ := reachRequest(t, h, principaltest.User(1), `{nope`); status != 200 {
		t.Errorf("malformed body: %d", status)
	}
	h.Check.cache = nil
	h.Check.inFlight = nil
	// Six checks per minute and account.
	limited := &fakeLimiter{counts: map[string]int{"overview_reachability:user:1": checkRateLimit}}
	h.Limiter = limited
	if status, out := reachRequest(t, h, principaltest.User(1), `{"ids":["a"]}`); status != 429 || out["code"] != "busy" {
		t.Errorf("rate limit: %d %v", status, out)
	}
	h.Limiter = &fakeLimiter{}
	h.Check.inFlight = map[int64]bool{1: true}
	h.Check.cache = map[int64]cached{}
	if status, out := reachRequest(t, h, principaltest.User(1), `{"ids":["a"]}`); status != 429 || out["error"] != "A check is still running." {
		t.Errorf("in flight: %d %v", status, out)
	}
	h.Check.inFlight = map[int64]bool{7: true, 8: true, 9: true}
	if status, out := reachRequest(t, h, principaltest.User(1), `{"ids":["a"]}`); status != 429 || out["error"] != "Other checks are running. Try again shortly." {
		t.Errorf("busy process: %d %v", status, out)
	}
}

func TestReachabilityDeadlineLeavesHostsUnchecked(t *testing.T) {
	h, prober, _ := reachFixture([]ReachHost{{ID: "slow", Host: "slow", Port: 22}}, map[string]string{"slow:22": "hold"})
	prober.release = make(chan struct{})
	defer close(prober.release)
	h.Check.deadline = 50 * time.Millisecond
	_, body := reachRequest(t, h, principaltest.User(1), "")
	if got := body["results"].(map[string]any)["slow"].(map[string]any)["state"]; got != "unchecked" {
		t.Fatalf("slow host: %v", got)
	}
}

func TestReachabilityBlockedNamesLookUnresolved(t *testing.T) {
	h, _, _ := reachFixture([]ReachHost{{ID: "n", Host: "nowhere", Port: 22}}, map[string]string{"nowhere:22": "unresolved"})
	h.Check.BlockInternal = true
	_, body := reachRequest(t, h, principaltest.User(1), "")
	if got := body["results"].(map[string]any)["n"].(map[string]any)["state"]; got != "blocked" {
		t.Fatalf("with BLOCK_INTERNAL_SSH a name that does not resolve is %v", got)
	}
}

func TestReachabilityPlansAtMostFiftyHosts(t *testing.T) {
	var hosts []ReachHost
	for i := range MaxProbes + 5 {
		hosts = append(hosts, ReachHost{ID: "h" + itoa(i), Host: "h", Port: 22})
	}
	r := &Reachability{Canonical: canonicalLower}
	plans, sig := r.plans(principaltest.User(1), hosts, nil)
	if len(plans) != MaxProbes {
		t.Fatalf("%d plans", len(plans))
	}
	other, sig2 := r.plans(principaltest.User(1), hosts, map[string]bool{"h1": true})
	if len(other) != 1 || sig == sig2 {
		t.Fatalf("wanted plans: %d", len(other))
	}
}

// fakeTailnet lets user 1 launch the hosts in may and routes those in
// routed through the tailnet, where tailnet answers them.
type fakeTailnet struct {
	may, routed map[string]bool
	tailnet     *fakeProber
}

func (f *fakeTailnet) MayLaunch(p principal.Principal, host string, _ int, user string) bool {
	return p.UserID == 1 && f.may[host] && user == "root"
}

func (f *fakeTailnet) DialTailnet(ctx context.Context, p principal.Principal, host string, port int, user string) (Conn, bool, error) {
	if !f.MayLaunch(p, host, port, user) || !f.routed[host] {
		return nil, false, nil
	}
	conn, err := f.tailnet.DialProbe(ctx, host, port)
	return conn, true, err
}

// HO2-2: a direct Tailscale SSH host the caller may launch is reached
// over its authorized tailnet route, not refused by the tailnet route
// restriction of the network policy; without the authorization or the
// route it is probed as any other host.
func TestReachabilityUsesTheTailnetAuthorization(t *testing.T) {
	hosts := []ReachHost{
		{ID: "node", Host: "node.ts.net", Port: 22, AuthType: "tailscale", Username: "root"},
		{ID: "down", Host: "down.ts.net", Port: 22, AuthType: "tailscale", Username: "root"},
		{ID: "denied", Host: "denied.ts.net", Port: 22, AuthType: "tailscale", Username: "root"},
		{ID: "other-user", Host: "node.ts.net", Port: 22, AuthType: "tailscale", Username: "admin"},
		{ID: "no-route", Host: "lan.example", Port: 22, AuthType: "tailscale", Username: "root"},
		{ID: "key", Host: "node.ts.net", Port: 2222, AuthType: "key", Username: "root"},
	}
	// The ordinary policy refuses every tailnet node.
	h, prober, greetings := reachFixture(hosts, map[string]string{
		"node.ts.net:22": "blocked", "down.ts.net:22": "blocked", "denied.ts.net:22": "blocked",
		"node.ts.net:2222": "blocked", "lan.example:22": "ssh:SSH-2.0-OpenSSH_9.6\r\n",
	})
	tn := &fakeTailnet{
		may:     map[string]bool{"node.ts.net": true, "down.ts.net": true, "lan.example": true},
		routed:  map[string]bool{"node.ts.net": true, "down.ts.net": true},
		tailnet: &fakeProber{script: map[string]string{"node.ts.net:22": "ssh:SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"}},
	}
	h.Check.Tailnet = tn
	h.Check.deadline = 3 * time.Second
	status, body := reachRequest(t, h, principaltest.User(1), "")
	if status != 200 {
		t.Fatalf("check: %d %v", status, body)
	}
	results := body["results"].(map[string]any)
	want := map[string]string{"node": "reachable", "down": "unreachable", "denied": "blocked",
		"other-user": "blocked", "no-route": "reachable", "key": "blocked"}
	for id, s := range want {
		if got := results[id].(map[string]any)["state"]; got != s {
			t.Errorf("%s: %v, want %s", id, got, s)
		}
	}
	// Only the host with a remote user outside the allowlist reaches
	// node.ts.net through the network policy.
	policyDials := map[string]int{}
	for _, d := range prober.dials() {
		policyDials[d]++
	}
	if policyDials["node.ts.net:22"] != 1 || policyDials["down.ts.net:22"] != 0 {
		t.Errorf("authorized tailnet hosts went through the network policy: %v", policyDials)
	}
	if g := greetings.seen["node"]; g.Platform != "ubuntu" {
		t.Errorf("tailnet greeting %+v", greetings.seen)
	}
	// A change of the authorization is another set of destinations.
	r := h.Check
	_, before := r.plans(principaltest.User(1), hosts, nil)
	tn.may["node.ts.net"] = false
	_, after := r.plans(principaltest.User(1), hosts, nil)
	if before == after {
		t.Error("the signature ignores the tailnet authorization")
	}
}
