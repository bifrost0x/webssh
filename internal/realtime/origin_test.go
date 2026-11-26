package realtime

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOriginPolicy(t *testing.T) {
	proxied := func(scheme, host string) func(*http.Request) (string, string) {
		return func(*http.Request) (string, string) { return scheme, host }
	}
	legacy := OriginPolicy{IgnoreScheme: true}
	tests := []struct {
		name    string
		policy  OriginPolicy
		host    string
		tls     bool
		origins []string // nil: no header
		want    error
	}{
		// The 22 cases of the K6 spike.
		{"same origin", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:5000"}, nil},
		{"same origin, case and trailing dot", OriginPolicy{}, "WebSSH.lab:5000", false, []string{"http://webssh.LAB.:5000"}, nil},
		{"default port written out", OriginPolicy{}, "webssh.lab", true, []string{"https://webssh.lab:443"}, nil},
		{"ipv6", OriginPolicy{}, "[::1]:5000", false, []string{"http://[::1]:5000"}, nil},
		{"missing Origin", OriginPolicy{}, "webssh.lab:5000", false, nil, ErrOriginMissing},
		{"empty Origin", OriginPolicy{}, "webssh.lab:5000", false, []string{""}, ErrOriginMissing},
		{"two Origin headers", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:5000", "http://evil"}, ErrOriginInvalid},
		{"null origin", OriginPolicy{}, "webssh.lab:5000", false, []string{"null"}, ErrOriginInvalid},
		{"file scheme", OriginPolicy{}, "webssh.lab:5000", false, []string{"file://"}, ErrOriginInvalid},
		{"userinfo", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://a@webssh.lab:5000"}, ErrOriginInvalid},
		{"path", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:5000/x"}, ErrOriginInvalid},
		{"other host", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://evil.lab:5000"}, ErrOriginDenied},
		{"prefix collision host", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab.evil:5000"}, ErrOriginDenied},
		{"other port, same host", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:8080"}, ErrOriginDenied},
		{"scheme mismatch (https page, plain listener)", OriginPolicy{}, "webssh.lab", false, []string{"https://webssh.lab"}, ErrOriginDenied},
		{"scheme mismatch (http page, TLS listener)", OriginPolicy{}, "webssh.lab", true, []string{"http://webssh.lab"}, ErrOriginDenied},
		{"allowlist exact", OriginPolicy{Allowed: []string{"https://ssh.example.com"}}, "10.0.0.2:5000", false, []string{"https://ssh.example.com"}, nil},
		{"allowlist other scheme", OriginPolicy{Allowed: []string{"https://ssh.example.com"}}, "10.0.0.2:5000", false, []string{"http://ssh.example.com"}, ErrOriginDenied},
		{"allowlist subdomain", OriginPolicy{Allowed: []string{"https://example.com"}}, "10.0.0.2:5000", false, []string{"https://a.example.com"}, ErrOriginDenied},
		{"allow any still needs a valid Origin", OriginPolicy{AllowAny: true}, "x", false, nil, ErrOriginMissing},
		{"allow any", OriginPolicy{AllowAny: true}, "x", false, []string{"http://evil"}, nil},
		{"trusted proxy scheme", OriginPolicy{Self: proxied("https", "webssh.lab")}, "webssh.lab", false, []string{"https://webssh.lab"}, nil},

		// Review gaps of the spike (K6-Z4) and production additions.
		{"real suffix host", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://evilwebssh.lab:5000"}, ErrOriginDenied},
		{"parent domain", OriginPolicy{}, "a.webssh.lab:5000", false, []string{"http://webssh.lab:5000"}, ErrOriginDenied},
		{"trailing slash", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:5000/"}, ErrOriginInvalid},
		{"query", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:5000?x"}, ErrOriginInvalid},
		{"fragment", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:5000#x"}, ErrOriginInvalid},
		{"port zero", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:0"}, ErrOriginInvalid},
		{"port out of range", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:70000"}, ErrOriginInvalid},
		{"leading zeros in port", OriginPolicy{}, "webssh.lab:5000", false, []string{"http://webssh.lab:05000"}, nil},
		{"ws scheme", OriginPolicy{}, "webssh.lab:5000", false, []string{"ws://webssh.lab:5000"}, ErrOriginInvalid},
		{"unbracketed ipv6", OriginPolicy{}, "[::1]:5000", false, []string{"http://::1:5000"}, ErrOriginInvalid},
		{"trusted proxy host", OriginPolicy{Self: proxied("https", "ssh.example.com")}, "10.0.0.2:5000", false, []string{"https://ssh.example.com"}, nil},
		{"trusted proxy says http", OriginPolicy{Self: proxied("http", "webssh.lab")}, "webssh.lab", true, []string{"https://webssh.lab"}, ErrOriginDenied},
		{"allowlist does not replace own origin", OriginPolicy{Allowed: []string{"https://ssh.example.com"}}, "webssh.lab:5000", false, []string{"http://webssh.lab:5000"}, nil},

		// "Do not check the scheme", kept for upgraded installations (D-01 B,
		// K6 A1): the Python rule of same_origin_socket_check.
		{"legacy: https page behind untrusted TLS proxy", legacy, "webssh.lab", false, []string{"https://webssh.lab"}, nil},
		{"legacy: http page", legacy, "webssh.lab:5000", false, []string{"http://webssh.lab:5000"}, nil},
		{"legacy: Host port read with the page's default", legacy, "webssh.lab:443", false, []string{"https://webssh.lab"}, nil},
		{"legacy: default ports differ", legacy, "webssh.lab", false, []string{"https://webssh.lab:80"}, ErrOriginDenied},
		{"legacy: host still compared", legacy, "webssh.lab", false, []string{"https://evil.lab"}, ErrOriginDenied},
		{"legacy: port still compared", legacy, "webssh.lab:5000", false, []string{"https://webssh.lab:5001"}, ErrOriginDenied},
		{"legacy: missing Origin still refused", legacy, "webssh.lab", false, nil, ErrOriginMissing},
		{"legacy: null still refused", legacy, "webssh.lab", false, []string{"null"}, ErrOriginInvalid},
		{"legacy: allowlist stays exact", OriginPolicy{IgnoreScheme: true, Allowed: []string{"https://ssh.example.com"}}, "10.0.0.2", false, []string{"http://ssh.example.com"}, ErrOriginDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.policy
			if _, err := p.Compile(); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/ws", nil)
			r.Host = tt.host
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for _, o := range tt.origins {
				r.Header.Add("Origin", o)
			}
			if err := p.Check(r); !errors.Is(err, tt.want) {
				t.Fatalf("Check = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOriginPolicyCompile(t *testing.T) {
	if _, err := (&OriginPolicy{Allowed: []string{"https://a.example", "*"}}).Compile(); err == nil {
		t.Fatal("Compile accepted '*'")
	}
	bad := []string{"ssh.example.com", "ftp://x", "https://x/path", "https://x/", "https://u@x", "https://x:99999", "null"}
	p := OriginPolicy{Allowed: append([]string{" https://a.example ", "", "https://B.example:443"}, bad...)}
	ignored, err := p.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.allowed) != 2 || len(ignored) != len(bad) {
		t.Fatalf("allowed %v, ignored %v", p.allowed, ignored)
	}
	// An ignored entry never matches, as in Python.
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.Host = "10.0.0.2"
	r.Header.Set("Origin", "https://x")
	if err := p.Check(r); !errors.Is(err, ErrOriginDenied) {
		t.Fatalf("Check = %v", err)
	}
}

func TestKeepLegacySchemeRule(t *testing.T) {
	tests := []struct {
		wildcard, anyOrigin bool
		proxies             int
		cidrs               []string
		want                bool
	}{
		{true, false, 0, nil, true},
		{true, true, 0, nil, false},  // any origin: nothing to keep
		{true, false, 1, nil, false}, // a trusted proxy reports the scheme
		{true, false, 0, []string{"10.0.0.0/8"}, false},
		{false, false, 0, nil, false}, // explicit list: Python compared exactly
	}
	for _, tt := range tests {
		if got := KeepLegacySchemeRule(tt.wildcard, tt.anyOrigin, tt.proxies, tt.cidrs); got != tt.want {
			t.Errorf("KeepLegacySchemeRule(%v, %v, %d, %v) = %v, want %v", tt.wildcard, tt.anyOrigin, tt.proxies, tt.cidrs, got, tt.want)
		}
	}
}
