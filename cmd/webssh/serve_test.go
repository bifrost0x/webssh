package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

func TestParseServeOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		addr    string
		dataDir string
		wantErr string
	}{
		{name: "defaults like python start.py", addr: "127.0.0.1:5000", dataDir: "/app/data"},
		{name: "HOST and PORT", env: map[string]string{"HOST": "0.0.0.0", "PORT": "8080"}, addr: "0.0.0.0:8080", dataDir: "/app/data"},
		{name: "IPv6 HOST", env: map[string]string{"HOST": "::"}, addr: "[::]:5000", dataDir: "/app/data"},
		{name: "empty values use defaults", env: map[string]string{"HOST": "", "PORT": "", "DATA_DIR": ""}, addr: "127.0.0.1:5000", dataDir: "/app/data"},
		{name: "DATA_DIR", env: map[string]string{"DATA_DIR": "/srv/webssh"}, addr: "127.0.0.1:5000", dataDir: "/srv/webssh"},
		{name: "bind overrides HOST and PORT", args: []string{"--bind", "0.0.0.0:5000"}, env: map[string]string{"HOST": "127.0.0.1", "PORT": "8080"}, addr: "0.0.0.0:5000", dataDir: "/app/data"},
		{name: "bind with equals", args: []string{"--bind=[::1]:5001"}, addr: "[::1]:5001", dataDir: "/app/data"},
		{name: "invalid PORT", env: map[string]string{"PORT": "50a0"}, wantErr: "PORT"},
		{name: "PORT zero", env: map[string]string{"PORT": "0"}, wantErr: "PORT"},
		{name: "PORT too large", env: map[string]string{"PORT": "65536"}, wantErr: "PORT"},
		{name: "PORT with URL parts", env: map[string]string{"PORT": "80@evil.example"}, wantErr: "PORT"},
		{name: "bind without port", args: []string{"--bind", "0.0.0.0"}, wantErr: "--bind"},
		{name: "bind with bad port", args: []string{"--bind", "0.0.0.0:http"}, wantErr: "--bind"},
		{name: "positional", args: []string{"now"}, wantErr: "positional"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts, err := parseServeOptions(tt.args, lookupFrom(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opts.addr != tt.addr || opts.dataDir != tt.dataDir || opts.shutdownTimeout != shutdownGrace {
				t.Errorf("opts = %+v, want addr %s, data dir %s", opts, tt.addr, tt.dataDir)
			}
		})
	}
}

func TestListenNetwork(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]string{
		"0.0.0.0:5000":            "tcp4",
		"127.0.0.1:5000":          "tcp4",
		"[::]:5000":               "tcp",
		"[::1]:5000":              "tcp",
		"[::ffff:127.0.0.1]:5000": "tcp",
		"localhost:5000":          "tcp",
		":5000":                   "tcp",
		"garbage":                 "tcp",
	} {
		if got := listenNetwork(addr); got != want {
			t.Errorf("listenNetwork(%q) = %q, want %q", addr, got, want)
		}
	}
}

// HOST=:: must answer over IPv4 and IPv6, as the Python servers do, so the
// healthcheck (127.0.0.1) still finds it.
func TestServeUnspecifiedIPv6IsDualStack(t *testing.T) {
	var lc net.ListenConfig
	probe, err := lc.Listen(t.Context(), "tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	opts, err := parseServeOptions(nil, lookupFrom(map[string]string{"HOST": "::", "PORT": "5000"}))
	if err != nil {
		t.Fatal(err)
	}
	if opts.addr != "[::]:5000" {
		t.Fatalf("addr %q", opts.addr)
	}
	r := startServe(t, serveOptions{addr: "[::]:0"}, nil)
	_, port, err := net.SplitHostPort(r.addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		if code, _ := getJSON(t, "http://"+net.JoinHostPort(host, port)+"/ready"); code != http.StatusOK {
			t.Errorf("/ready over %s: %d", host, code)
		}
	}
	t.Setenv("PORT", port)
	if code, _, stderr := runArgs(t, "webssh", "healthcheck"); code != 0 {
		t.Errorf("healthcheck against [::]:%s: %d %s", port, code, stderr)
	}
}

func TestParseServeOptionsTimeZone(t *testing.T) {
	t.Parallel()
	opts, err := parseServeOptions(nil, lookupFrom(map[string]string{"TZ": "Europe/Berlin"}))
	if err != nil || !opts.tzSet || opts.tz != "Europe/Berlin" {
		t.Fatalf("opts = %+v, %v", opts, err)
	}
	opts, err = parseServeOptions(nil, lookupFrom(nil))
	if err != nil || opts.tzSet {
		t.Fatalf("unset TZ: opts = %+v, %v", opts, err)
	}
}

// syncBuffer collects log output written from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type running struct {
	addr   string
	cancel context.CancelFunc
	force  chan struct{}
	done   chan error
	logs   *syncBuffer
}

func startServe(t *testing.T, opts serveOptions, build buildFunc) *running {
	t.Helper()
	if opts.addr == "" {
		opts.addr = "127.0.0.1:0"
	}
	if opts.dataDir == "" {
		opts.dataDir = filepath.Join(t.TempDir(), "data")
	}
	if opts.shutdownTimeout == 0 {
		opts.shutdownTimeout = 5 * time.Second
	}
	if build == nil {
		build = buildProbeApplication
	}
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	r := &running{cancel: cancel, force: make(chan struct{}), done: make(chan error, 1), logs: logs}
	addrCh := make(chan string, 1)
	go func() {
		r.done <- serve(ctx, opts, slog.New(slog.NewTextHandler(logs, nil)), build, r.force,
			func(a net.Addr) { addrCh <- a.String() })
	}()
	select {
	case r.addr = <-addrCh:
	case err := <-r.done:
		cancel()
		t.Fatalf("serve ended before ready: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("serve did not become ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(10 * time.Second):
			t.Error("serve did not stop")
		}
	})
	return r
}

func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err // for Cleanup
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
		return nil
	}
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func TestServeReadyAndGracefulShutdown(t *testing.T) {
	t.Parallel()
	dataDir := filepath.Join(t.TempDir(), "data")
	r := startServe(t, serveOptions{dataDir: dataDir}, nil)

	if code, body := getJSON(t, "http://"+r.addr+"/health"); code != http.StatusOK || body["status"] != "ok" {
		t.Errorf("health: %d %v", code, body)
	}
	if code, body := getJSON(t, "http://"+r.addr+"/ready"); code != http.StatusOK || body["status"] != "ready" {
		t.Errorf("ready: %d %v", code, body)
	}
	for _, sub := range []string{"", "logs", "keys"} {
		info, err := os.Stat(filepath.Join(dataDir, sub))
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", sub, info, err)
		}
	}
	if err := r.stop(t); err != nil {
		t.Fatalf("serve: %v", err)
	}
	logs := r.logs.String()
	for _, want := range []string{"msg=ready", "msg=\"shutdown requested\"", "msg=\"shutdown complete\""} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s:\n%s", want, logs)
		}
	}
}

func TestServeRefusesRelativeDataDir(t *testing.T) {
	t.Parallel()
	opts := serveOptions{addr: "127.0.0.1:0", dataDir: "data", shutdownTimeout: time.Second}
	err := serve(t.Context(), opts, slog.New(slog.DiscardHandler), buildProbeApplication, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v, want the absolute path error", err)
	}
}

func TestServeFailsWhenPortIsTaken(t *testing.T) {
	t.Parallel()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	opts := serveOptions{addr: ln.Addr().String(), dataDir: t.TempDir(), shutdownTimeout: time.Second}
	err = serve(t.Context(), opts, slog.New(slog.DiscardHandler), buildProbeApplication, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("err = %v, want a listen error", err)
	}
}

func TestServeWarnsAboutUnknownTimeZone(t *testing.T) {
	t.Parallel()
	r := startServe(t, serveOptions{tz: "Invalid/Zone", tzSet: true}, nil)
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if logs := r.logs.String(); !strings.Contains(logs, `msg="time zone not applied"`) || !strings.Contains(logs, "Invalid/Zone") {
		t.Errorf("no time zone warning:\n%s", logs)
	}
	r = startServe(t, serveOptions{tz: "Europe/Berlin", tzSet: true}, nil)
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if logs := r.logs.String(); strings.Contains(logs, "time zone") {
		t.Errorf("warning for a valid zone:\n%s", logs)
	}
}

// blockingApp holds one request and one long-lived connection open, the way
// a terminal WebSocket does, and reports what shutdown did to them.
type blockingApp struct {
	entered  chan struct{}
	release  chan struct{}
	drained  chan struct{}
	stopping func() bool
}

func newBlockingApp() *blockingApp {
	return &blockingApp{entered: make(chan struct{}), release: make(chan struct{}), drained: make(chan struct{})}
}

func (b *blockingApp) build(state *runtimeState) (application, error) {
	b.stopping = state.Stopping
	mux := http.NewServeMux()
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, r *http.Request) {
		close(b.entered)
		select {
		case <-b.release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	})
	drain := func(ctx context.Context) error {
		defer close(b.drained)
		select {
		case <-b.release:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return application{handler: mux, drain: drain}, nil
}

func startSlowRequest(t *testing.T, r *running, b *blockingApp) chan int {
	t.Helper()
	status := make(chan int, 1)
	go func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+r.addr+"/slow", nil)
		if err != nil {
			status <- -1
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			status <- 0
			return
		}
		resp.Body.Close()
		status <- resp.StatusCode
	}()
	<-b.entered
	return status
}

func TestShutdownWaitsForRunningWork(t *testing.T) {
	t.Parallel()
	b := newBlockingApp()
	r := startServe(t, serveOptions{}, b.build)
	status := startSlowRequest(t, r, b)
	r.cancel()
	// Shutdown has begun but must wait for the request and the drain.
	deadline := time.Now().Add(5 * time.Second)
	for !b.stopping() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-r.done:
		t.Fatalf("serve returned before work finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(b.release)
	if err := <-r.done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	r.done <- nil
	if got := <-status; got != http.StatusNoContent {
		t.Errorf("slow request status %d, want 204", got)
	}
}

func TestShutdownDeadline(t *testing.T) {
	t.Parallel()
	b := newBlockingApp()
	r := startServe(t, serveOptions{shutdownTimeout: 200 * time.Millisecond}, b.build)
	status := startSlowRequest(t, r, b)
	begin := time.Now()
	err := r.stop(t)
	if !errors.Is(err, errShutdownDeadline) {
		t.Fatalf("err = %v, want errShutdownDeadline", err)
	}
	if took := time.Since(begin); took > 3*time.Second {
		t.Errorf("shutdown took %v", took)
	}
	<-b.drained
	<-status
}

func TestShutdownForcedBySecondSignal(t *testing.T) {
	t.Parallel()
	b := newBlockingApp()
	r := startServe(t, serveOptions{shutdownTimeout: time.Minute}, b.build)
	status := startSlowRequest(t, r, b)
	r.cancel()
	for !b.stopping() {
		time.Sleep(5 * time.Millisecond)
	}
	begin := time.Now()
	close(r.force)
	err := <-r.done
	r.done <- err
	if !errors.Is(err, errShutdownForced) {
		t.Fatalf("err = %v, want errShutdownForced", err)
	}
	if took := time.Since(begin); took > 3*time.Second {
		t.Errorf("forced shutdown took %v", took)
	}
	<-status
}

func TestReadyReportsStoppingAndDataDirectory(t *testing.T) {
	t.Parallel()
	state := &runtimeState{dataDir: t.TempDir(), logger: slog.New(slog.DiscardHandler)}
	app, err := buildProbeApplication(state)
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, app.handler)
	if code, _ := getJSON(t, srv+"/ready"); code != http.StatusOK {
		t.Fatalf("ready %d", code)
	}
	state.stopping.Store(true)
	code, body := getJSON(t, srv+"/ready")
	if code != http.StatusServiceUnavailable || body["status"] != "not_ready" || !strings.Contains(strings.Join(anyStrings(body["failed"]), ","), "runtime") {
		t.Errorf("stopping: %d %v", code, body)
	}

	missing := &runtimeState{dataDir: filepath.Join(t.TempDir(), "gone"), logger: slog.New(slog.DiscardHandler)}
	app, err = buildProbeApplication(missing)
	if err != nil {
		t.Fatal(err)
	}
	srv = newTestServer(t, app.handler)
	code, body = getJSON(t, srv+"/ready")
	if code != http.StatusServiceUnavailable || strings.Join(anyStrings(body["failed"]), ",") != "data_directory" {
		t.Errorf("missing data directory: %d %v", code, body)
	}
}

func anyStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func TestCachedProbe(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	p := &cachedProbe{dir: dir, ttl: probeTTL, now: func() time.Time { return now }}
	if err := p.check(); err != nil {
		t.Fatal(err)
	}
	// Within the interval a passed probe is reused, even if the directory
	// has gone since.
	p.dir = filepath.Join(dir, "gone")
	now = now.Add(probeTTL - time.Second)
	if err := p.check(); err != nil {
		t.Errorf("cached probe ran again: %v", err)
	}
	now = now.Add(2 * time.Second)
	if err := p.check(); err == nil {
		t.Error("expired probe did not run again")
	}
	// A failure is not cached.
	p.dir = dir
	if err := p.check(); err != nil {
		t.Errorf("probe after recovery: %v", err)
	}
}
