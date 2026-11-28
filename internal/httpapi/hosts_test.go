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
