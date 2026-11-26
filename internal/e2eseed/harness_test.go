package e2eseed

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// fakeBackend is the smallest backend the harness can start: it answers
// GET /login like the readiness probe of playwright.config.js expects.
type fakeBackend struct {
	stores  *fakeStores
	env     Env
	routes  []protocol.Route
	ready   chan string
	closed  bool
	serveFn func(ctx context.Context, ln net.Listener) error
}

func (f *fakeBackend) wire(_ context.Context, env Env) (*Backend, error) {
	f.env = env
	return &Backend{
		Stores: f.stores.stores(),
		Hooks:  Hooks{OutputFlow: newFakeFlow(0), FixtureSessions: &fakeSessions{}},
		Serve: func(ctx context.Context, ln net.Listener, routes []protocol.Route) error {
			f.routes = routes
			if f.serveFn != nil {
				return f.serveFn(ctx, ln)
			}
			srv := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/login" {
						http.NotFound(w, r)
						return
					}
					_, _ = io.WriteString(w, "login")
				}),
				ReadHeaderTimeout: time.Second,
			}
			go func() { <-ctx.Done(); _ = srv.Close() }()
			f.ready <- ln.Addr().String()
			if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
		Close: func() error { f.closed = true; return nil },
	}, nil
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func options(t *testing.T) Options {
	t.Helper()
	return Options{SeedPath: checkedInSeed, Port: freePort(t), TempDir: t.TempDir(), Environ: []string{"AUTOMATION_ENABLED=1"}}
}

func TestRunServesAfterTheSeed(t *testing.T) {
	t.Parallel()
	o := options(t)
	o.FastHashing = true
	f := &fakeBackend{stores: newFakeStores(), ready: make(chan string, 1)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, o, f.wire) }()
	var addr string
	select {
	case addr = <-f.ready:
	case err := <-done:
		t.Fatalf("Run ended early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("backend did not become ready")
	}
	if addr != "127.0.0.1:"+strconv.Itoa(o.Port) {
		t.Fatalf("listening on %s", addr)
	}
	// Everything was seeded before the port opened.
	if len(f.stores.users) != 4 || len(f.stores.profiles) != 2 || len(f.routes) != 2 {
		t.Fatalf("users=%d profiles=%d routes=%d", len(f.stores.users), len(f.stores.profiles), len(f.routes))
	}
	resp, err := http.Get("http://" + addr + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d", resp.StatusCode)
	}
	env := f.env
	if !env.FastHashing || env.Dialer == nil || !strings.HasPrefix(env.DataDir, o.TempDir) {
		t.Fatalf("env = %+v", env)
	}
	if v, _ := env.Lookup("DATA_DIR"); v != env.DataDir {
		t.Fatalf("DATA_DIR = %q", v)
	}
	if _, set := env.Lookup("AUTOMATION_ENABLED"); set {
		t.Fatal("unset_environment ignored")
	}
	if secret, err := os.ReadFile(filepath.Join(env.DataDir, "oidc-client-secret")); err != nil || string(secret) != "e2e-only-oidc-secret" {
		t.Fatalf("data file: %q %v", secret, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
	if !f.closed {
		t.Fatal("backend not closed")
	}
	if _, err := os.Stat(filepath.Dir(env.DataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("scratch tree left behind")
	}
}

// listening reports whether something accepts connections on port.
func listening(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err == nil {
		c.Close()
	}
	return err == nil
}

func TestRunFailsClosedBeforeListening(t *testing.T) {
	t.Parallel()
	badSeed := filepath.Join(t.TempDir(), "seed.json")
	if err := os.WriteFile(badSeed, []byte(`{"version": 2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(o *Options, f *fakeBackend) Wire{
		"seed version": func(o *Options, f *fakeBackend) Wire { o.SeedPath = badSeed; return f.wire },
		"wire error": func(_ *Options, _ *fakeBackend) Wire {
			return func(context.Context, Env) (*Backend, error) { return nil, errors.New("no stores") }
		},
		"nothing to serve": func(_ *Options, _ *fakeBackend) Wire {
			return func(context.Context, Env) (*Backend, error) { return &Backend{}, nil }
		},
		"store error": func(_ *Options, f *fakeBackend) Wire { f.stores.failOn = "profiles 1 23"; return f.wire },
		"hook provider missing": func(_ *Options, f *fakeBackend) Wire {
			return func(ctx context.Context, env Env) (*Backend, error) {
				b, err := f.wire(ctx, env)
				b.Hooks.OutputFlow = nil
				return b, err
			}
		},
		"invalid port": func(o *Options, f *fakeBackend) Wire { o.Port = 0; return f.wire },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := options(t)
			f := &fakeBackend{stores: newFakeStores(), ready: make(chan string, 1)}
			wire := setup(&o, f)
			if err := Run(t.Context(), o, wire); err == nil {
				t.Fatal("Run succeeded")
			}
			if len(f.ready) != 0 || (o.Port > 0 && listening(o.Port)) {
				t.Fatal("port opened after a failed start")
			}
			if entries, _ := os.ReadDir(o.TempDir); len(entries) != 0 {
				t.Fatalf("scratch tree left behind: %v", entries)
			}
		})
	}
}

func TestRunReportsServeErrors(t *testing.T) {
	t.Parallel()
	o := options(t)
	var once sync.Once
	f := &fakeBackend{stores: newFakeStores(), ready: make(chan string, 1)}
	f.serveFn = func(context.Context, net.Listener) error {
		var err error
		once.Do(func() { err = errors.New("listener broke") })
		return err
	}
	o.Log = slog.New(slog.DiscardHandler)
	if err := Run(t.Context(), o, f.wire); err == nil || !strings.Contains(err.Error(), "listener broke") {
		t.Fatalf("Run = %v", err)
	}
}

func TestRunRefusesABusyPort(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	o := options(t)
	o.Port = ln.Addr().(*net.TCPAddr).Port
	f := &fakeBackend{stores: newFakeStores(), ready: make(chan string, 1)}
	if err := Run(t.Context(), o, f.wire); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("Run = %v", err)
	}
}
