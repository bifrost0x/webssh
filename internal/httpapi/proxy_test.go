package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func resolveWith(hops int, cidrs []string, remote string, headers map[string]string) requestInfo {
	var prefixes []netip.Prefix
	for _, c := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(c))
	}
	t := newProxyTrust(hops, prefixes, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodGet, "http://direct.test/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		for part := range strings.SplitSeq(v, "\n") {
			r.Header.Add(k, part)
		}
	}
	return t.resolve(r)
}

func TestClientAddress(t *testing.T) {
	cases := []struct {
		name   string
		hops   int
		cidrs  []string
		remote string
		xff    string
		want   string
	}{
		{"no proxy trust ignores XFF", 0, nil, "198.51.100.1:1000", "203.0.113.5", "198.51.100.1"},
		{"one hop takes the last value", 1, nil, "10.0.0.2:1000", "203.0.113.5, 192.0.2.1", "192.0.2.1"},
		{"two hops", 2, nil, "10.0.0.2:1000", "203.0.113.5, 192.0.2.1", "203.0.113.5"},
		{"several headers are one list", 2, nil, "10.0.0.2:1000", "203.0.113.5\n192.0.2.1", "203.0.113.5"},
		{"fewer values than hops keeps the peer", 3, nil, "10.0.0.2:1000", "203.0.113.5, 192.0.2.1", "10.0.0.2"},
		{"no header keeps the peer", 1, nil, "10.0.0.2:1000", "", "10.0.0.2"},
		{"peer inside the CIDRs", 1, []string{"10.0.0.0/8"}, "10.0.0.2:1000", "203.0.113.5", "203.0.113.5"},
		{"peer outside the CIDRs", 1, []string{"10.0.0.0/8"}, "198.51.100.1:1000", "203.0.113.5", "198.51.100.1"},
		{"mapped peer is unmapped before the CIDR check", 1, []string{"10.0.0.0/8"}, "[::ffff:10.0.0.2]:1000", "203.0.113.5", "203.0.113.5"},
		{"mapped CIDR matches the IPv4 peer", 1, []string{"::ffff:10.0.0.0/104"}, "10.0.0.2:1000", "203.0.113.5", "203.0.113.5"},
		{"mapped client is unmapped", 1, nil, "10.0.0.2:1000", "::ffff:203.0.113.5", "203.0.113.5"},
		{"client with port", 1, nil, "10.0.0.2:1000", "203.0.113.5:4711", "203.0.113.5"},
		{"intermediate address outside the CIDRs is the client", 2, []string{"10.0.0.0/8"}, "10.0.0.2:1000", "203.0.113.5, 198.51.100.9", "198.51.100.9"},
		{"intermediate address inside the CIDRs", 2, []string{"10.0.0.0/8"}, "10.0.0.2:1000", "203.0.113.5, 10.1.1.1", "203.0.113.5"},
		{"malformed value keeps the peer", 1, nil, "10.0.0.2:1000", "not-an-ip", "10.0.0.2"},
		{"IPv6 peer with zone", 0, nil, "[fe80::1%eth0]:1000", "", "fe80::1"},
	}
	for _, c := range cases {
		info := resolveWith(c.hops, c.cidrs, c.remote, map[string]string{"X-Forwarded-For": c.xff})
		if got := info.Client.String(); got != c.want {
			t.Errorf("%s: client %s, want %s", c.name, got, c.want)
		}
	}
}

func TestForwardedSchemeHostPrefix(t *testing.T) {
	h := map[string]string{
		"X-Forwarded-For": "203.0.113.5", "X-Forwarded-Proto": "https",
		"X-Forwarded-Host": "ssh.example.com", "X-Forwarded-Prefix": "/tools/webssh/",
	}
	info := resolveWith(1, nil, "10.0.0.2:1", h)
	if info.Scheme != "https" || info.Host != "ssh.example.com" || info.BasePath != "/tools/webssh" {
		t.Fatalf("%+v", info)
	}
	// Untrusted: nothing applies.
	info = resolveWith(0, nil, "10.0.0.2:1", h)
	if info.Scheme != "http" || info.Host != "direct.test" || info.BasePath != "" {
		t.Fatalf("untrusted %+v", info)
	}
	info = resolveWith(1, []string{"192.168.0.0/16"}, "10.0.0.2:1", h)
	if info.Host != "direct.test" || info.BasePath != "" {
		t.Fatalf("outside the CIDRs %+v", info)
	}
	// Malformed values are ignored.
	for header, value := range map[string]string{
		"X-Forwarded-Proto":  "javascript",
		"X-Forwarded-Host":   "evil.test/path",
		"X-Forwarded-Prefix": "//evil.test",
	} {
		bad := map[string]string{"X-Forwarded-For": "203.0.113.5", header: value}
		info := resolveWith(1, nil, "10.0.0.2:1", bad)
		if info.Scheme != "http" || info.Host != "direct.test" || info.BasePath != "" {
			t.Errorf("%s=%q applied: %+v", header, value, info)
		}
	}
}

func TestValidHostAndPrefix(t *testing.T) {
	for v, want := range map[string]bool{
		"ssh.example.com": true, "ssh.example.com:8443": true, "192.0.2.1": true, "[2001:db8::1]": true,
		"[2001:db8::1]:443": true, "": false, "a b": false, "a/b": false, "a@b": false, "[::1": false,
		"2001:db8::1": false, "host:": false, "host:x": false, "[fe80::1%eth0]": false, `a\b`: false,
	} {
		if validHost(v) != want {
			t.Errorf("validHost(%q) = %v", v, !want)
		}
	}
	for v, want := range map[string]string{"/": "", "/a": "/a", "/a/b/": "/a/b"} {
		if got, ok := cleanPrefix(v); !ok || got != want {
			t.Errorf("cleanPrefix(%q) = %q %v", v, got, ok)
		}
	}
	for _, v := range []string{"a", "//x", "/a//b", "/a/../b", "/./a", `/a\b`, "/a b", `/a"b`, "/a%2e"} {
		if _, ok := cleanPrefix(v); ok {
			t.Errorf("cleanPrefix(%q) accepted", v)
		}
	}
}

func TestProxyWarningsAreLoggedOnce(t *testing.T) {
	var logs strings.Builder
	p := newProxyTrust(0, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	for range 3 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Forwarded-For", "203.0.113.5")
		p.resolve(r)
	}
	if n := strings.Count(logs.String(), "TRUSTED_PROXIES=0"); n != 1 {
		t.Fatalf("warning logged %d times", n)
	}
}

func FuzzProxyResolve(f *testing.F) {
	f.Add("203.0.113.5, 10.0.0.1", "https", "h:1", "/p", "10.0.0.2:1")
	f.Add("[::1]:2,x", "HTTP", "[::1]", "/a/../b", "[::ffff:10.0.0.2]:9")
	f.Fuzz(func(t *testing.T, xff, proto, host, prefix, remote string) {
		info := resolveWith(2, []string{"10.0.0.0/8"}, remote, map[string]string{
			"X-Forwarded-For": xff, "X-Forwarded-Proto": proto, "X-Forwarded-Host": host, "X-Forwarded-Prefix": prefix,
		})
		if info.Scheme != "http" && info.Scheme != "https" {
			t.Fatalf("scheme %q", info.Scheme)
		}
		if info.BasePath != "" {
			if _, ok := cleanPrefix(info.BasePath); !ok || strings.HasSuffix(info.BasePath, "/") {
				t.Fatalf("base path %q", info.BasePath)
			}
		}
		if info.Client.IsValid() && (info.Client.Is4In6() || info.Client.Zone() != "") {
			t.Fatalf("client %v not normalised", info.Client)
		}
	})
}
