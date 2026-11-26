package httpapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
)

// requestInfo is what the edge learned about a request before routing:
// the client address and, for trusted proxies, what the browser used.
type requestInfo struct {
	// Client is the address used for rate limits and audit, unmapped and
	// without zone. Invalid when the peer address could not be parsed.
	Client netip.Addr
	// Scheme is "https" or "http" as the browser used it.
	Scheme string
	// Host is the host[:port] the browser addressed.
	Host string
	// BasePath is the path prefix the browser sees (X-Forwarded-Prefix of
	// a trusted proxy, like SCRIPT_NAME in the Python release), "" at the
	// root. It never ends with a slash.
	BasePath string
}

type infoKey struct{}

func withInfo(ctx context.Context, info requestInfo) context.Context {
	return context.WithValue(ctx, infoKey{}, info)
}

func infoFrom(r *http.Request) requestInfo {
	if info, ok := r.Context().Value(infoKey{}).(requestInfo); ok {
		return info
	}
	return directInfo(r)
}

func directInfo(r *http.Request) requestInfo {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return requestInfo{Client: peerAddr(r.RemoteAddr), Scheme: scheme, Host: r.Host}
}

// ClientAddr returns the client address of a request that passed the
// edge: the peer, or the address a trusted proxy reported. It is the
// address for sign-in limits and audit.
func ClientAddr(r *http.Request) netip.Addr { return infoFrom(r).Client }

// Origin returns the scheme and host the browser used for a request. It
// is the realtime endpoint's OriginPolicy.Self.
func Origin(r *http.Request) (scheme, host string) {
	info := infoFrom(r)
	return info.Scheme, info.Host
}

// BasePath returns the path prefix the browser sees for a request; links,
// redirects and asset URLs start with it.
func BasePath(r *http.Request) string { return infoFrom(r).BasePath }

// proxyTrust applies TRUSTED_PROXIES and TRUSTED_PROXY_CIDRS (D-19).
//
// The hop count works like Werkzeug's ProxyFix in the Python release: of
// each forwarding header the hops-th value from the right counts, and a
// header with fewer values is ignored. With CIDRs, forwarding headers
// count only on connections from those networks, and each address that
// the walk passes on its way to the client must be in them as well; the
// first address outside is the client. Every address is unmapped before it
// is compared, so ::ffff:10.0.0.1 and 10.0.0.1 are the same peer.
type proxyTrust struct {
	hops  int
	cidrs []netip.Prefix
	log   *slog.Logger

	warnedUntrusted atomic.Bool
	warnedBypass    atomic.Bool
	warnedOutside   atomic.Bool
	warnedInvalid   atomic.Bool
}

func newProxyTrust(hops int, cidrs []netip.Prefix, log *slog.Logger) *proxyTrust {
	t := &proxyTrust{hops: hops, log: log}
	for _, p := range cidrs {
		t.cidrs = append(t.cidrs, unmapPrefix(p))
	}
	return t
}

// unmapPrefix turns an IPv4-mapped IPv6 prefix into its IPv4 form, so it
// matches unmapped addresses.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
	}
	return p
}

func normaliseAddr(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

func peerAddr(remote string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return normaliseAddr(ap.Addr())
	}
	if a, err := netip.ParseAddr(remote); err == nil {
		return normaliseAddr(a)
	}
	return netip.Addr{}
}

// parseForwardedAddr reads one X-Forwarded-For value: an address,
// optionally with a port.
func parseForwardedAddr(v string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(v); err == nil {
		return normaliseAddr(a), true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return normaliseAddr(ap.Addr()), true
	}
	return netip.Addr{}, false
}

func (t *proxyTrust) trusted(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range t.cidrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// headerList splits all values of a list header like the WSGI server
// joins them: by commas, trimmed.
func headerList(h http.Header, name string) []string {
	var out []string
	for _, v := range h.Values(name) {
		for part := range strings.SplitSeq(v, ",") {
			out = append(out, strings.TrimSpace(part))
		}
	}
	return out
}

// realValue is ProxyFix's _get_real_value: the hops-th value from the
// right, or "" when there are fewer.
func (t *proxyTrust) realValue(h http.Header, name string) string {
	values := headerList(h, name)
	if t.hops == 0 || len(values) < t.hops {
		return ""
	}
	return values[len(values)-t.hops]
}

// resolve computes the request info. It never fails: a forwarding value
// that is not well formed is ignored and logged once.
func (t *proxyTrust) resolve(r *http.Request) requestInfo {
	info := directInfo(r)
	t.note(r, info.Client)
	if t.hops == 0 || (len(t.cidrs) > 0 && !t.trusted(info.Client)) {
		return info
	}
	if client, ok := t.forwardedClient(r.Header); ok {
		info.Client = client
	}
	if proto := strings.ToLower(t.realValue(r.Header, "X-Forwarded-Proto")); proto != "" {
		if proto == "http" || proto == "https" {
			info.Scheme = proto
		} else {
			t.invalid("X-Forwarded-Proto")
		}
	}
	if host := t.realValue(r.Header, "X-Forwarded-Host"); host != "" {
		if validHost(host) {
			info.Host = host
		} else {
			t.invalid("X-Forwarded-Host")
		}
	}
	if prefix := t.realValue(r.Header, "X-Forwarded-Prefix"); prefix != "" {
		if p, ok := cleanPrefix(prefix); ok {
			info.BasePath = p
		} else {
			t.invalid("X-Forwarded-Prefix")
		}
	}
	return info
}

func (t *proxyTrust) forwardedClient(h http.Header) (netip.Addr, bool) {
	values := headerList(h, "X-Forwarded-For")
	if len(values) == 0 || (len(values) == 1 && values[0] == "") {
		return netip.Addr{}, false
	}
	if len(values) < t.hops {
		return netip.Addr{}, false
	}
	// Walk from the proxy next to us towards the client.
	for i := len(values) - 1; i >= len(values)-t.hops; i-- {
		a, ok := parseForwardedAddr(values[i])
		if !ok {
			t.invalid("X-Forwarded-For")
			return netip.Addr{}, false
		}
		if i == len(values)-t.hops || (len(t.cidrs) > 0 && !t.trusted(a)) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// validHost accepts host[:port] as a browser sends it in Host: a name, an
// IPv4 address or a bracketed IPv6 address, nothing that changes the
// meaning of a URL.
func validHost(v string) bool {
	if v == "" || len(v) > 255 || strings.ContainsAny(v, "/\\@?#% \t\"'<>") {
		return false
	}
	host, bracketed := v, false
	if h, port, err := net.SplitHostPort(v); err == nil {
		if port == "" || strings.Trim(port, "0123456789") != "" {
			return false
		}
		host, bracketed = h, strings.HasPrefix(v, "[")
	} else if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		host, bracketed = v[1:len(v)-1], true
	}
	if bracketed {
		a, err := netip.ParseAddr(host)
		return err == nil && a.Is6() && a.Zone() == ""
	}
	return host != "" && !strings.ContainsAny(host, "[]:")
}

// cleanPrefix accepts a path prefix that starts with one slash and has no
// empty, "." or ".." segments; the trailing slash is dropped as Flask does
// for script_root. "/" is the root.
func cleanPrefix(v string) (string, bool) {
	if !strings.HasPrefix(v, "/") || len(v) > 512 {
		return "", false
	}
	trimmed := strings.TrimRight(v, "/")
	if trimmed == "" {
		return "", true
	}
	for seg := range strings.SplitSeq(trimmed[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
		for _, c := range seg {
			if c < 0x21 || c == 0x7f || strings.ContainsRune("\\\"'<>%?#", c) {
				return "", false
			}
		}
	}
	return trimmed, true
}

// note logs once per process when traffic contradicts the proxy
// settings, as the Python release does. A client can trigger these lines,
// so they only advise and never change a decision.
func (t *proxyTrust) note(r *http.Request, peer netip.Addr) {
	forwarded := r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != ""
	switch {
	case t.hops == 0:
		if forwarded && t.warnedUntrusted.CompareAndSwap(false, true) {
			t.log.Warn("requests carry X-Forwarded-For or Forwarded headers but TRUSTED_PROXIES=0; behind a reverse proxy all clients then share the proxy address for sign-in limits and audit logs; set TRUSTED_PROXIES to the number of proxies in front of WebSSH", "proxy", peer.String())
		}
	case len(t.cidrs) > 0 && !t.trusted(peer):
		if forwarded && t.warnedOutside.CompareAndSwap(false, true) {
			t.log.Warn("forwarding headers from an address outside TRUSTED_PROXY_CIDRS are ignored", "peer", peer.String())
		}
	case r.Header.Get("X-Forwarded-For") == "" && !peer.IsLoopback():
		if t.warnedBypass.CompareAndSwap(false, true) {
			t.log.Warn("a request reached WebSSH without X-Forwarded-For although TRUSTED_PROXIES is set; clients that bypass the proxy can choose the address used for sign-in limits and audit logs; publish the port only to the proxy or set TRUSTED_PROXY_CIDRS", "client", peer.String())
		}
	}
}

func (t *proxyTrust) invalid(header string) {
	if t.warnedInvalid.CompareAndSwap(false, true) {
		t.log.Warn("a trusted proxy sent a forwarding header that is not well formed; it is ignored", "header", header)
	}
}
