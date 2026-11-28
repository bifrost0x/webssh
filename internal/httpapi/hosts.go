package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/config"
)

// hostPolicy is ALLOWED_HOSTS: the DNS names the server answers to. A
// page whose name an attacker rebinds to the server's address would
// otherwise pass the origin checks, which compare with the host the
// browser used. IP literals and localhost cannot be rebound and are
// always served, so are the hosts of CORS_ORIGINS. A nil policy (no
// ALLOWED_HOSTS) serves every name, as the Python release did.
type hostPolicy struct {
	names map[string]bool
}

func newHostPolicy(o config.Origins) *hostPolicy {
	if len(o.AllowedHosts) == 0 {
		return nil
	}
	p := &hostPolicy{names: map[string]bool{}}
	for _, name := range o.AllowedHosts {
		p.names[name] = true
	}
	for _, origin := range o.List {
		if u, err := url.Parse(origin); err == nil && u.Hostname() != "" {
			p.names[hostName(u.Hostname())] = true
		}
	}
	return p
}

// allows reports whether host (host[:port] as the browser sent it) may be
// served.
func (p *hostPolicy) allows(host string) bool {
	if p == nil {
		return true
	}
	name, literal := requestHostName(host)
	return literal || (name != "" && p.names[name])
}

// requestHosts returns the hosts a request names: the Host header and,
// when it differs, the host the edge resolved (X-Forwarded-Host behind a
// trusted proxy). A host check must hold for each of them. A proxy that
// passes the client's X-Forwarded-Host on unchanged hands the client the
// resolved value, so it may narrow what Host allows but never widen it.
func requestHosts(r *http.Request) []string {
	if resolved := infoFrom(r).Host; resolved != r.Host {
		return []string{r.Host, resolved}
	}
	return []string{r.Host}
}

// refusedHost returns the first host of the request that allowed rejects.
func refusedHost(r *http.Request, allowed func(string) bool) (string, bool) {
	for _, host := range requestHosts(r) {
		if !allowed(host) {
			return host, true
		}
	}
	return "", false
}

func hostName(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }

// misdirected answers 421 to a request for a host name outside
// ALLOWED_HOSTS. It reads nothing of the request and logs at most one
// refusal a minute, with the host name, so that an operator who moved
// the server to a new name finds the cause.
func (h *Handler) misdirected(w http.ResponseWriter, r *http.Request, host string) {
	now := time.Now().Unix()
	if last := h.lastHostLog.Load(); now-last >= 60 && h.lastHostLog.CompareAndSwap(last, now) {
		h.log.Warn("request for a host name outside ALLOWED_HOSTS refused", "host", truncate(host, 200))
	}
	w.Header().Set("Connection", "close")
	writePlain(w, http.StatusMisdirectedRequest, "This server does not answer to that host name.")
}

// FirstAccountHost returns the check of the first-account registration:
// while no account exists, the browser may register (and so become
// administrator) only through a host name nobody can rebind to this
// server, an IP literal or localhost, or through a name of allowed
// (ALLOWED_HOSTS). Behind a trusted proxy both the Host header and
// X-Forwarded-Host must qualify (requestHosts). The hosts of CORS_ORIGINS
// do not count: with CORS_ORIGINS=* they would admit every name.
func FirstAccountHost(allowed []string) func(*http.Request) bool {
	names := map[string]bool{}
	for _, n := range allowed {
		names[hostName(n)] = true
	}
	qualifies := func(host string) bool {
		name, literal := requestHostName(host)
		return literal || (name != "" && names[name])
	}
	return func(r *http.Request) bool {
		_, refused := refusedHost(r, qualifies)
		return !refused
	}
}

// requestHostName is the lower-case name of host (host[:port] as the
// browser sent it) without port, brackets or trailing dot; literal
// reports an IP literal or localhost, which cannot be rebound.
func requestHostName(host string) (name string, literal bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	name = hostName(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if name == "" {
		return "", false
	}
	_, err := netip.ParseAddr(name)
	return name, err == nil || name == "localhost"
}
