package hostops

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

func waitScan(t *testing.T, s *Scanner, p principal.Principal, id string) ScanView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		v, err := s.View(p, id)
		if err != nil {
			t.Fatal(err)
		}
		if v.State != "running" {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("scan did not end")
	return ScanView{}
}

func mustPrefix(t *testing.T, network string) (netip.Prefix, []netip.Addr) {
	t.Helper()
	p, addrs, err := parseNetwork(network)
	if err != nil {
		t.Fatal(err)
	}
	return p, addrs
}

func TestScanReportsOnlySSHServersAndNeverSends(t *testing.T) {
	prober := &fakeProber{script: map[string]string{
		"10.0.0.3:22":   "ssh:SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
		"10.0.0.1:2222": "ssh:SSH-2.0-dropbear_2022.83\r\n",
		"10.0.0.2:22":   "text:HTTP/1.1 400 Bad Request\r\n",
		"10.0.0.4:22":   "blocked",
		"10.0.0.5:22":   "silent",
	}}
	audit := &fakeAudit{}
	s := &Scanner{Dialer: prober, Audit: audit, interval: time.Millisecond}
	prefix, addrs := mustPrefix(t, "10.0.0.0/29")
	p := principaltest.User(7)
	v, err := s.Start(t.Context(), p, prefix, addrs, []int{22, 2222}, map[string]bool{"10.0.0.1|2222": true})
	if err != nil || v.State != "running" || v.Total != 12 || v.Network != "10.0.0.0/29" {
		t.Fatalf("start: %+v %v", v, err)
	}
	v = waitScan(t, s, p, v.ID)
	if v.State != "done" || v.Checked != 12 || v.Blocked != 1 || v.FinishedAt == nil {
		t.Fatalf("finished scan: %+v", v)
	}
	if len(v.Found) != 2 || v.Found[0].Address != "10.0.0.1" || v.Found[1].Address != "10.0.0.3" {
		t.Fatalf("found: %+v", v.Found)
	}
	if !v.Found[0].Known || v.Found[1].Known || *v.Found[0].Platform != "embedded" || *v.Found[1].Platform != "ubuntu" ||
		v.Found[1].Software != "OpenSSH 9.6p1" || v.Found[1].Comment != "Ubuntu-3ubuntu13.5" {
		t.Fatalf("found entries: %+v %+v", v.Found[0], v.Found[1])
	}
	if n := prober.written.Load(); n != 0 {
		t.Fatalf("the scan sent %d bytes", n)
	}
	if peak := prober.peak.Load(); peak > scanInFlight {
		t.Fatalf("%d probes in flight", peak)
	}
	if got := audit.all(); !slices.Equal(got, []string{"HOST_DISCOVERY_STARTED", "HOST_DISCOVERY_FINISHED"}) {
		t.Fatalf("audit events %v", got)
	}
}

func TestScanLimits(t *testing.T) {
	prober := &fakeProber{script: map[string]string{}, release: make(chan struct{})}
	for i := range 4 {
		prober.script["10.0.0."+itoa(i)+":22"] = "hold"
	}
	s := &Scanner{Dialer: prober, interval: time.Millisecond}
	prefix, addrs := mustPrefix(t, "10.0.0.0/30")
	a, b, c := principaltest.User(1), principaltest.User(2), principaltest.User(3)
	first, err := s.Start(t.Context(), a, prefix, addrs, []int{22}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(t.Context(), a, prefix, addrs, []int{22}, nil); err != errScanRunning {
		t.Fatalf("second scan of one account: %v", err)
	}
	if _, err := s.Start(t.Context(), b, prefix, addrs, []int{22}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(t.Context(), c, prefix, addrs, []int{22}, nil); err != errScanBusy {
		t.Fatalf("third scan in the process: %v", err)
	}
	// Another account sees no scan; the owner can cancel it.
	if _, err := s.View(b, first.ID); err != errScanGone {
		t.Fatalf("foreign view: %v", err)
	}
	if _, err := s.Cancel(b, first.ID); err != errScanGone {
		t.Fatalf("foreign cancel: %v", err)
	}
	v, err := s.Cancel(a, first.ID)
	if err != nil || v.State != "cancelled" {
		t.Fatalf("cancel: %+v %v", v, err)
	}
	close(prober.release)
	if v := waitScan(t, s, a, first.ID); v.State != "cancelled" {
		t.Fatalf("cancelled scan ended as %s", v.State)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestScanRevocationForgetsResults(t *testing.T) {
	prober := &fakeProber{script: map[string]string{"10.0.0.1:22": "ssh:SSH-2.0-OpenSSH_9.6\r\n"}}
	s := &Scanner{Dialer: prober, interval: time.Millisecond}
	prefix, addrs := mustPrefix(t, "10.0.0.1/32")
	p := principal.Principal{UserID: 4, SessionID: "browser-1"}
	other := principal.Principal{UserID: 4, SessionID: "browser-2"}
	v, err := s.Start(t.Context(), p, prefix, addrs, []int{22}, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitScan(t, s, p, v.ID)
	s.Revoked(principal.Revocation{UserID: 4, SessionID: "browser-2"})
	if got, err := s.View(other, v.ID); err != nil || len(got.Found) != 1 {
		t.Fatalf("another session's revocation touched the scan: %+v %v", got, err)
	}
	s.Revoked(principal.Revocation{UserID: 4, SessionID: "browser-1"})
	if _, err := s.View(p, v.ID); err != errScanGone {
		t.Fatalf("revoked scan still visible: %v", err)
	}
}

func discoveryRequest(t *testing.T, h *DiscoveryHTTP, p *principal.Principal, method, path, body string) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	h.Register(mux)
	return serveMux(t, mux, p, method, path, body)
}

func serveMux(t *testing.T, mux *http.ServeMux, p *principal.Principal, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if p != nil {
		req = req.WithContext(principal.With(req.Context(), *p))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%s %s: cacheable answer", method, path)
	}
	var out map[string]any
	_ = json.Unmarshal(bytes.TrimSpace(rec.Body.Bytes()), &out)
	return rec.Code, out
}

func TestDiscoveryHTTP(t *testing.T) {
	prober := &fakeProber{script: map[string]string{}}
	permitted := map[int64]bool{1: true}
	accepting := true
	h := &DiscoveryHTTP{
		Scanner: &Scanner{Dialer: prober, interval: time.Millisecond}, Enabled: true,
		Permitted: func(_ context.Context, p principal.Principal) (bool, error) { return permitted[p.UserID], nil },
		Known:     func(context.Context, int64) (map[string]bool, error) { return map[string]bool{}, nil },
		Limiter:   &fakeLimiter{}, Accepting: func() bool { return accepting },
	}
	user, other := principaltest.User(1), principaltest.User(2)
	cases := []struct {
		name, body string
		p          *principal.Principal
		status     int
		code       string
	}{
		{"no principal", `{"network":"10.0.0.0/30"}`, nil, 401, ""},
		{"not permitted", `{"network":"10.0.0.0/30"}`, &other, 403, "forbidden"},
		{"extra member", `{"network":"10.0.0.0/30","x":1}`, &user, 400, "invalid_request"},
		{"no object", `["10.0.0.0/30"]`, &user, 400, "invalid_request"},
		{"bad network", `{"network":"10.0.0.0/22"}`, &user, 400, "invalid_network"},
		{"network not a string", `{"network":5}`, &user, 400, "invalid_network"},
		{"too many ports", `{"network":"10.0.0.0/30","ports":[1,2,3,4]}`, &user, 400, "invalid_network"},
	}
	for _, c := range cases {
		status, body := discoveryRequest(t, h, c.p, "POST", "/api/discovery/scans", c.body)
		if status != c.status || (c.code != "" && body["code"] != c.code) {
			t.Errorf("%s: %d %v", c.name, status, body)
		}
	}
	if _, body := discoveryRequest(t, h, &user, "POST", "/api/discovery/scans", `{"network":"10.0.0.0/22"}`); body["error"] != "Choose a range of at most 256 addresses (for example a /24)." {
		t.Errorf("size message: %v", body["error"])
	}
	status, body := discoveryRequest(t, h, &user, "POST", "/api/discovery/scans", `{"network":" 10.0.0.0/30 ","ports":[22,22]}`)
	if status != 202 || body["state"] != "running" || body["network"] != "10.0.0.0/30" || body["total"] != 2.0 {
		t.Fatalf("start: %d %v", status, body)
	}
	id := body["id"].(string)
	waitScan(t, h.Scanner, user, id)
	if status, body := discoveryRequest(t, h, &user, "GET", "/api/discovery/scans/"+id, ""); status != 200 || body["state"] != "done" {
		t.Fatalf("view: %d %v", status, body)
	}
	if status, body := discoveryRequest(t, h, &other, "GET", "/api/discovery/scans/"+id, ""); status != 404 || body["code"] != "not_found" {
		t.Fatalf("foreign view: %d %v", status, body)
	}
	// Ten scans per hour and account.
	for range 9 {
		status, body := discoveryRequest(t, h, &user, "POST", "/api/discovery/scans", `{"network":"10.0.0.1"}`)
		if status != 202 {
			t.Fatalf("scan within the limit: %d", status)
		}
		waitScan(t, h.Scanner, user, body["id"].(string))
	}
	if status, body := discoveryRequest(t, h, &user, "POST", "/api/discovery/scans", `{"network":"10.0.0.1"}`); status != 429 || body["code"] != "busy" {
		t.Fatalf("eleventh scan: %d %v", status, body)
	}
	accepting = false
	if status, body := discoveryRequest(t, h, &user, "POST", "/api/discovery/scans", `{"network":"10.0.0.1"}`); status != 503 || body["code"] != "unavailable" {
		t.Fatalf("maintenance: %d %v", status, body)
	}
	h.Enabled = false
	if status, body := discoveryRequest(t, h, &user, "POST", "/api/discovery/scans", `{"network":"10.0.0.1"}`); status != 404 || body["code"] != "unavailable" {
		t.Fatalf("disabled: %d %v", status, body)
	}
	if h.Available(t.Context(), user) {
		t.Fatal("available while HOST_DISCOVERY_ENABLED is off")
	}
	if err := h.Scanner.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Scanner.Start(t.Context(), user, netip.MustParsePrefix("10.0.0.1/32"), nil, []int{22}, nil); err != errNoWork {
		t.Fatalf("scan after shutdown: %v", err)
	}
}
