package realtime

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// OriginPolicy decides which pages may open a realtime connection.
// Browsers cannot add custom headers to a WebSocket upgrade, so the Origin
// check together with the SameSite session cookie is the CSRF defence of
// the endpoint (ADR 0005, D-20).
//
// The zero value accepts only the application's own origin, compared by
// scheme, host and port. Call Compile before the first Check.
type OriginPolicy struct {
	// Allowed are further origins (CORS_ORIGINS), compared exactly after
	// normalising scheme, host and port. "*" is not an origin: the caller
	// maps CORS_ORIGINS=* (ALLOW_CORS_WILDCARD) to an empty list, which
	// keeps the same-origin rule the Python release applies to it.
	Allowed []string
	// AllowAny keeps the documented meaning of SOCKETIO_ALLOW_ANY_ORIGIN
	// with CORS_ORIGINS=*: any well-formed origin is accepted. An upgrade
	// without Origin is still refused.
	AllowAny bool
	// IgnoreScheme compares only host and port with the application's own
	// origin, as the Python release does for CORS_ORIGINS=*. It exists for
	// installations that run behind a TLS-terminating proxy that is not
	// trusted (TRUSTED_PROXIES=0): this server sees "http" while the
	// browser sends "https". The one-time migration pins it as an explicit
	// setting for such installations (D-01, option B; see
	// KeepLegacySchemeRule); new installations compare the scheme. It does
	// not apply to Allowed, whose entries always match exactly.
	IgnoreScheme bool
	// Self returns the scheme and host the browser used for this request.
	// The HTTP edge supplies it from TLS and, for trusted proxies only,
	// from X-Forwarded-Proto and X-Forwarded-Host. Nil means: "https" when
	// TLS ends at this listener, otherwise "http", and the Host header.
	Self func(*http.Request) (scheme, host string)

	allowed map[origin]struct{}
}

type origin struct {
	scheme string
	host   string
	port   string
}

func (o origin) String() string { return o.scheme + "://" + net.JoinHostPort(o.host, o.port) }

// Errors returned by Check. The endpoint answers all of them with HTTP 403
// before any session lookup.
var (
	ErrOriginMissing = errors.New("realtime: upgrade without Origin header")
	ErrOriginInvalid = errors.New("realtime: malformed Origin header")
	ErrOriginDenied  = errors.New("realtime: origin not allowed")
)

// maxOriginLen bounds what is parsed; browsers send far shorter values.
const maxOriginLen = 2048

// KeepLegacySchemeRule reports whether an installation upgraded from the
// Python release keeps the scheme-blind same-origin rule (D-01 option B,
// K6 deviation A1). It holds exactly when the Python release compared
// host and port only (CORS_ORIGINS=* without SOCKETIO_ALLOW_ANY_ORIGIN)
// and no proxy was trusted to report the browser's scheme. The migration
// evaluates it once for the legacy configuration and records the result
// as an explicit setting, which then sets OriginPolicy.IgnoreScheme; new
// installations never evaluate it.
func KeepLegacySchemeRule(corsWildcard, allowAnyOrigin bool, trustedProxies int, trustedProxyCIDRs []string) bool {
	return corsWildcard && !allowAnyOrigin && trustedProxies == 0 && len(trustedProxyCIDRs) == 0
}

// Compile validates the allowlist once at start, so that a typo fails the
// start instead of silently refusing every browser.
func (p *OriginPolicy) Compile() error {
	allowed := make(map[origin]struct{}, len(p.Allowed))
	for _, raw := range p.Allowed {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if raw == "*" {
			return errors.New("realtime: '*' is not an origin; CORS_ORIGINS=* means the same-origin rule")
		}
		o, err := parseOrigin(raw)
		if err != nil {
			return fmt.Errorf("realtime: allowed origin %q: %w", raw, err)
		}
		allowed[o] = struct{}{}
	}
	p.allowed = allowed
	return nil
}

// Check accepts or refuses an upgrade request. Without Compile only the
// own origin is accepted.
func (p *OriginPolicy) Check(r *http.Request) error {
	values := r.Header.Values("Origin")
	if len(values) == 0 || (len(values) == 1 && values[0] == "") {
		return ErrOriginMissing
	}
	if len(values) > 1 {
		return ErrOriginInvalid
	}
	got, err := parseOrigin(values[0])
	if err != nil {
		return ErrOriginInvalid
	}
	if p.AllowAny {
		return nil
	}
	scheme, host := p.self(r)
	if p.IgnoreScheme {
		// The Python rule: the Host header is read with the default port
		// of the scheme the page claims, so http://h and https://h:443
		// both match a request for "h" on their own default port.
		scheme = got.scheme
	}
	if own, err := normalise(scheme, host); err == nil && own == got {
		return nil
	}
	if _, ok := p.allowed[got]; ok {
		return nil
	}
	return ErrOriginDenied
}

func (p *OriginPolicy) self(r *http.Request) (scheme, host string) {
	if p.Self != nil {
		return p.Self(r)
	}
	if r.TLS != nil {
		return "https", r.Host
	}
	return "http", r.Host
}

// parseOrigin accepts the serialisation browsers send (RFC 6454, section
// 6.2): scheme, host and optional port, nothing else. "null", userinfo,
// paths, queries and fragments are refused.
func parseOrigin(raw string) (origin, error) {
	if len(raw) > maxOriginLen {
		return origin{}, errors.New("too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return origin{}, err
	}
	if u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return origin{}, errors.New("not a bare origin")
	}
	return normalise(u.Scheme, u.Host)
}

// normalise lowercases scheme and host, drops one trailing dot of the host
// and fills in the scheme's default port.
func normalise(scheme, hostport string) (origin, error) {
	scheme = strings.ToLower(scheme)
	var def string
	switch scheme {
	case "http":
		def = "80"
	case "https":
		def = "443"
	default:
		return origin{}, errors.New("scheme must be http or https")
	}
	if hostport == "" {
		return origin{}, errors.New("empty host")
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port; an IPv6 literal must then still be bracketed.
		host, port = hostport, ""
		if strings.HasPrefix(host, "[") {
			if !strings.HasSuffix(host, "]") {
				return origin{}, errors.New("bad host")
			}
			host = host[1 : len(host)-1]
		} else if strings.Contains(host, ":") {
			return origin{}, errors.New("bad host")
		}
	}
	if strings.ContainsAny(host, "[]") {
		return origin{}, errors.New("bad host")
	}
	port, err = normalisePort(port, def)
	if err != nil {
		return origin{}, err
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.ContainsAny(host, " /\\@?#%,;\t\r\n") {
		return origin{}, errors.New("bad host")
	}
	return origin{scheme: scheme, host: host, port: port}, nil
}

// normalisePort returns the decimal port without leading zeros, or the
// default for an empty value; it rejects values above 65535.
func normalisePort(port, def string) (string, error) {
	if port == "" {
		return def, nil
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", errors.New("bad port")
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return "", errors.New("bad port")
		}
	}
	if n == 0 {
		return "", errors.New("bad port")
	}
	return strconv.Itoa(n), nil
}
