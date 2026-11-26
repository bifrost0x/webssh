package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func portOf(t *testing.T, url string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func statusServer(t *testing.T, code int) string {
	t.Helper()
	return portOf(t, newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(code)
	})))
}

func TestHealthcheckPorts(t *testing.T) {
	t.Parallel()
	tests := map[string][]string{
		"":                {"5000"},
		"5000":            {"5000"},
		"8080":            {"8080", "5000"},
		"0":               {"5000"},
		"65536":           {"5000"},
		"80@evil.example": {"5000"},
		"80/../x":         {"5000"},
		" 8080":           {"5000"},
		"-1":              {"5000"},
	}
	for port, want := range tests {
		if got := healthcheckPorts(port); !slices.Equal(got, want) {
			t.Errorf("healthcheckPorts(%q) = %v, want %v", port, got, want)
		}
	}
}

func FuzzHealthcheckPorts(f *testing.F) {
	for _, s := range []string{"", "5000", "8080", "1@x", "65535", "99999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, port string) {
		for _, p := range healthcheckPorts(port) {
			if _, err := parsePort(p); err != nil {
				t.Fatalf("healthcheckPorts(%q) returned invalid port %q", port, p)
			}
			if strings.Trim(p, "0123456789") != "" {
				t.Fatalf("port %q has non-digits", p)
			}
		}
	})
}

// The healthcheck tests set PORT and therefore do not run in parallel.

func TestHealthcheckReady(t *testing.T) {
	t.Setenv("PORT", statusServer(t, http.StatusOK))
	if code, _, stderr := runArgs(t, "webssh", "healthcheck"); code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
}

func TestHealthcheckNotReady(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusFound, http.StatusNotFound} {
		t.Setenv("PORT", statusServer(t, status))
		code, _, stderr := runArgs(t, "webssh", "healthcheck", "-timeout", "500ms")
		if code != 1 || !strings.Contains(stderr, "not ready") {
			t.Errorf("status %d: code %d, stderr %q", status, code, stderr)
		}
	}
}

func TestHealthcheckDoesNotFollowRedirects(t *testing.T) {
	followed := false
	target := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed = true
	}))
	port := portOf(t, newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+"/ready", http.StatusFound)
	})))
	t.Setenv("PORT", port)
	if code, _, _ := runArgs(t, "webssh", "healthcheck", "-timeout", "500ms"); code != 1 {
		t.Errorf("code %d, want 1", code)
	}
	if followed {
		t.Error("healthcheck followed a redirect")
	}
}

func TestHealthcheckIgnoresProxyEnvironment(t *testing.T) {
	proxied := false
	proxy := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied = true
	}))
	t.Setenv("HTTP_PROXY", proxy)
	t.Setenv("http_proxy", proxy)
	t.Setenv("NO_PROXY", "")
	t.Setenv("PORT", statusServer(t, http.StatusOK))
	if code, _, stderr := runArgs(t, "webssh", "healthcheck"); code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if proxied {
		t.Error("healthcheck used the proxy")
	}
}

func TestHealthcheckWithoutServer(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PORT", port)
	// 5000 is tried as well; on a machine where something answers there
	// the result says nothing about the closed port.
	if code, _, _ := runArgs(t, "webssh", "healthcheck", "-timeout", "300ms"); code != 1 {
		t.Skip("port 5000 answers on this machine")
	}
}
