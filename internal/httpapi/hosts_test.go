package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bifrost0x/webssh/internal/config"
)

func hostEdge(t *testing.T, allowed []string, hops int) *edge {
	e := newEdge(t, withConfig(func(c *config.Config) {
		c.Origins.AllowedHosts = allowed
		c.Origins.List = []string{"https://other.example.org:8443", "not an origin"}
		c.Proxies.Hops = hops
	}))
	e.h.Mux().HandleFunc("GET /login", echo)
	e.h.Mux().HandleFunc("POST /register", echo)
	return e
}

func hostStatus(e *edge, method, target, host string, headers map[string]string) int {
	r := httptest.NewRequest(method, "http://placeholder"+target, nil)
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w.Code
}

// ALLOWED_HOSTS refuses a request addressed to any other DNS name with
// 421 before the session, the body and the realtime upgrade: a page whose
// name was rebound to the server's address cannot pass as same-origin.
// IP literals, localhost and the hosts of CORS_ORIGINS stay allowed.
func TestAllowedHostsRefusesOtherNames(t *testing.T) {
	e := hostEdge(t, []string{"ssh.example.com"}, 0)
	for _, tc := range []struct {
		method, target, host string
		want                 int
	}{
		{"GET", "/login", "ssh.example.com", http.StatusOK},
		{"GET", "/login", "SSH.Example.com.:5000", http.StatusOK},
		{"GET", "/login", "192.168.1.5:5000", http.StatusOK},
		{"GET", "/login", "[fd00::5]:5000", http.StatusOK},
		{"GET", "/login", "localhost:5000", http.StatusOK},
		{"GET", "/login", "other.example.org", http.StatusOK},
		{"GET", "/login", "rebind.attacker.test:5000", http.StatusMisdirectedRequest},
		{"POST", "/register", "rebind.attacker.test:5000", http.StatusMisdirectedRequest},
		{"GET", "/ws", "rebind.attacker.test", http.StatusMisdirectedRequest},
		{"GET", "/socket.io/", "rebind.attacker.test", http.StatusMisdirectedRequest},
		{"GET", "/login", "", http.StatusMisdirectedRequest},
		{"GET", "/health", "rebind.attacker.test", http.StatusOK},
	} {
		if got := hostStatus(e, tc.method, tc.target, tc.host, nil); got != tc.want {
			t.Errorf("%s %s Host %q: %d, want %d", tc.method, tc.target, tc.host, got, tc.want)
		}
	}
}

// Without ALLOWED_HOSTS every host is served, as in the Python release.
func TestNoAllowedHostsServesEveryName(t *testing.T) {
	e := hostEdge(t, nil, 0)
	if got := hostStatus(e, "GET", "/login", "rebind.attacker.test", nil); got != http.StatusOK {
		t.Fatalf("without ALLOWED_HOSTS: %d", got)
	}
}

// Behind a trusted proxy the host the browser used (X-Forwarded-Host)
// counts, not the proxy's own Host header.
func TestAllowedHostsBehindATrustedProxy(t *testing.T) {
	e := hostEdge(t, []string{"ssh.example.com"}, 1)
	if got := hostStatus(e, "GET", "/login", "webssh:5000", map[string]string{"X-Forwarded-Host": "ssh.example.com"}); got != http.StatusOK {
		t.Fatalf("forwarded allowed host: %d", got)
	}
	if got := hostStatus(e, "GET", "/login", "ssh.example.com", map[string]string{"X-Forwarded-Host": "rebind.attacker.test"}); got != http.StatusMisdirectedRequest {
		t.Fatalf("forwarded other host: %d", got)
	}
}

// The first account may be registered only through a name nobody can
// rebind: an IP literal, localhost or a name of ALLOWED_HOSTS, read
// after the proxy rules (X-Forwarded-Host behind a trusted proxy). The
// hosts of CORS_ORIGINS do not count, and without ALLOWED_HOSTS every DNS
// name is refused (finding #68).
func TestFirstAccountHost(t *testing.T) {
	for _, c := range []struct {
		name    string
		allowed []string
		hops    int
		host    string
		headers map[string]string
		want    bool
	}{
		{"IPv4 literal", nil, 0, "192.168.1.20:5000", nil, true},
		{"IPv6 literal", nil, 0, "[fd00::1]:5000", nil, true},
		{"localhost", nil, 0, "localhost:5000", nil, true},
		{"localhost with a trailing dot", nil, 0, "LOCALHOST.:5000", nil, true},
		{"DNS name without ALLOWED_HOSTS", nil, 0, "rebind.attacker.test:5000", nil, false},
		{"name of ALLOWED_HOSTS", []string{"ssh.example.com"}, 0, "SSH.example.com", nil, true},
		{"other name with ALLOWED_HOSTS", []string{"ssh.example.com"}, 0, "localhost.attacker.test", nil, false},
		{"host of CORS_ORIGINS", []string{"ssh.example.com"}, 0, "other.example.org:8443", nil, false},
		{"forwarded name behind a trusted proxy", []string{"ssh.example.com"}, 1, "webssh:5000",
			map[string]string{"X-Forwarded-Host": "ssh.example.com"}, true},
		{"forwarded name outside ALLOWED_HOSTS", nil, 1, "127.0.0.1:5000",
			map[string]string{"X-Forwarded-Host": "rebind.attacker.test"}, false},
		{"forwarded header without a trusted proxy", nil, 0, "rebind.attacker.test",
			map[string]string{"X-Forwarded-Host": "127.0.0.1"}, false},
	} {
		e := newEdge(t, withConfig(func(cfg *config.Config) {
			cfg.Origins.List = []string{"https://other.example.org:8443"}
			cfg.Origins.AllowedHosts = nil // the edge answers every name; the check alone decides
			cfg.Proxies.Hops = c.hops
		}))
		trusted := FirstAccountHost(c.allowed)
		var got bool
		e.h.Mux().HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) { got = trusted(r) })
		r := httptest.NewRequest("GET", "http://placeholder/login", nil)
		r.Host = c.host
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		e.h.ServeHTTP(httptest.NewRecorder(), r)
		if got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
