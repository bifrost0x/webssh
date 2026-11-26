package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/webssh/internal/buildinfo"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/platform"
)

const (
	// shutdownGrace bounds the graceful shutdown, as in the Python
	// application. Compose files give the container 40 s to stop.
	shutdownGrace = 30 * time.Second
	// defaultDataDir is the data directory of the image and of the Python
	// entrypoint when DATA_DIR is not set.
	defaultDataDir = "/app/data"
)

var (
	errShutdownForced   = errors.New("shutdown forced by a second signal")
	errShutdownDeadline = errors.New("graceful shutdown did not finish in time")
)

// serveOptions are the settings the server lifecycle needs. The full
// configuration is read by internal/config when the server is wired.
type serveOptions struct {
	addr            string
	dataDir         string
	shutdownTimeout time.Duration
	tz              string
	tzSet           bool
}

// parseServeOptions reads --bind, or else HOST and PORT with the defaults of
// "python start.py" (127.0.0.1:5000). The image passes --bind 0.0.0.0:5000,
// as its Gunicorn command did, so HOST and PORT keep meaning nothing for
// the listener there and the container port stays 5000.
func parseServeOptions(args []string, getenv func(string) (string, bool)) (serveOptions, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bind := fs.String("bind", "", "listen address host:port; overrides HOST and PORT")
	if err := fs.Parse(args); err != nil {
		return serveOptions{}, err
	}
	if fs.NArg() != 0 {
		return serveOptions{}, errors.New("serve takes no positional arguments")
	}
	opts := serveOptions{shutdownTimeout: shutdownGrace, dataDir: defaultDataDir}
	if dir, ok := getenv("DATA_DIR"); ok && dir != "" {
		opts.dataDir = dir
	}
	opts.tz, opts.tzSet = getenv("TZ")
	if *bind != "" {
		host, port, err := net.SplitHostPort(*bind)
		if err != nil {
			return serveOptions{}, fmt.Errorf("--bind: %w", err)
		}
		if _, err := parsePort(port); err != nil {
			return serveOptions{}, fmt.Errorf("--bind: %w", err)
		}
		opts.addr = net.JoinHostPort(host, port)
		return opts, nil
	}
	host := envOr(getenv, "HOST", "127.0.0.1")
	port := envOr(getenv, "PORT", "5000")
	if _, err := parsePort(port); err != nil {
		return serveOptions{}, fmt.Errorf("PORT: %w", err)
	}
	opts.addr = net.JoinHostPort(host, port)
	return opts, nil
}

// parsePort accepts a decimal TCP port from 1 to 65535.
func parsePort(s string) (int, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%q is not a port from 1 to 65535", s)
	}
	return int(n), nil
}

// listenNetwork binds an IPv4 literal to IPv4 only, so 0.0.0.0 listens on
// IPv4 as Gunicorn and Werkzeug do instead of Go's dual-stack default.
// Everything else uses "tcp": "::" is then dual-stack like the Python
// servers on Linux, and a host name resolves as before.
func listenNetwork(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		return "tcp4"
	}
	return "tcp"
}

func envOr(getenv func(string) (string, bool), name, fallback string) string {
	if v, ok := getenv(name); ok && v != "" {
		return v
	}
	return fallback
}

// runtimeState is shared between the lifecycle and the handlers.
type runtimeState struct {
	dataDir  string
	logger   *slog.Logger
	stopping atomic.Bool
}

// Stopping reports whether shutdown has begun; readiness turns false then.
func (s *runtimeState) Stopping() bool { return s.stopping.Load() }

// application is what serve runs.
type application struct {
	handler http.Handler
	// drain ends long-lived work that http.Server.Shutdown does not wait
	// for, such as hijacked WebSocket connections. It runs while the
	// server shuts down and must return when ctx ends. Optional.
	drain func(ctx context.Context) error
	// close releases the application after the server stopped: the
	// database, the audit log and the lock on the data directory.
	// Optional.
	close func() error
	// grace replaces the shutdown limit when it is set
	// (RUNTIME_SHUTDOWN_GRACE_SECONDS).
	grace time.Duration
}

// buildFunc builds the application. It prepares the data directory
// itself, in the order the configuration resolves it.
type buildFunc func(ctx context.Context, state *runtimeState) (application, error)

// buildSystem is the buildFunc of the server: the whole system of this
// build on the process environment.
func buildSystem(console io.Writer) buildFunc {
	return func(ctx context.Context, state *runtimeState) (application, error) {
		sys, err := openSystem(ctx, bootInput{lookup: os.LookupEnv, log: state.logger, console: console, stopping: state.Stopping})
		if err != nil {
			return application{}, err
		}
		return application{handler: sys.handler(), drain: sys.drain, close: sys.close, grace: sys.shutdownGrace()}, nil
	}
}

func runServe(ctx context.Context, args []string, s streams) int {
	opts, err := parseServeOptions(args, os.LookupEnv)
	if err != nil {
		return usageError(s.stderr, "serve: "+err.Error())
	}
	logger := slog.New(slog.NewTextHandler(s.stderr, nil))
	sigCtx, force, stop := withShutdownSignals(ctx)
	defer stop()
	if err := serve(sigCtx, opts, logger, buildSystem(s.stdout), force, nil); err != nil {
		logger.Error("server stopped", "err", err)
		return 1
	}
	return 0
}

// serve prepares the data directory, builds the application and serves HTTP
// until ctx ends, then shuts down gracefully within opts.shutdownTimeout or
// at once when force closes. ready, if set, receives the listen address.
func serve(ctx context.Context, opts serveOptions, logger *slog.Logger, build buildFunc, force <-chan struct{}, ready func(net.Addr)) error {
	started := time.Now()
	if err := platform.CheckTimeZone(opts.tz, opts.tzSet); err != nil {
		logger.Warn("time zone not applied", "err", err)
	}
	state := &runtimeState{dataDir: opts.dataDir, logger: logger}
	app, err := build(ctx, state)
	if err != nil {
		return fmt.Errorf("build application: %w", err)
	}
	if app.close != nil {
		defer func() {
			if cerr := app.close(); cerr != nil {
				logger.Error("release resources", "err", cerr)
			}
		}()
	}
	if app.grace > 0 {
		opts.shutdownTimeout = app.grace
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, listenNetwork(opts.addr), opts.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := &http.Server{
		Handler:           app.handler,
		ReadHeaderTimeout: 10 * time.Second, // ConfigureServer sets the edge's limits
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	httpapi.ConfigureServer(srv)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	if _, err := platform.Notify(platform.NotifyReady); err != nil {
		logger.Warn("service manager notification failed", "err", err)
	}
	logger.Info("ready", "version", buildinfo.Read().String(), "addr", ln.Addr().String(),
		"pid", os.Getpid(), "startup_ms", time.Since(started).Milliseconds())
	if ready != nil {
		ready(ln.Addr())
	}

	select {
	case err := <-serveErr:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}
	return shutdown(srv, app, state, opts.shutdownTimeout, force, serveErr)
}

// shutdown stops accepting work, lets running requests and long-lived
// connections finish within limit and closes everything that is left when
// the limit passes or force closes.
func shutdown(srv *http.Server, app application, state *runtimeState, limit time.Duration, force <-chan struct{}, serveErr <-chan error) error {
	begin := time.Now()
	logger := state.logger
	state.stopping.Store(true)
	if _, err := platform.Notify(platform.NotifyStopping); err != nil {
		logger.Warn("service manager notification failed", "err", err)
	}
	logger.Info("shutdown requested", "grace", limit)

	ctx, cancel := context.WithTimeoutCause(context.Background(), limit, errShutdownDeadline)
	defer cancel()
	forceCtx, cancelForce := context.WithCancelCause(ctx)
	defer cancelForce(nil)
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-force:
			cancelForce(errShutdownForced)
		case <-stopWatch:
		}
	}()

	var wg sync.WaitGroup
	var drainErr error
	if app.drain != nil {
		wg.Go(func() { drainErr = app.drain(forceCtx) })
	}
	err := srv.Shutdown(forceCtx)
	wg.Wait()
	if err != nil {
		closeErr := srv.Close()
		return errors.Join(fmt.Errorf("shutdown: %w", context.Cause(forceCtx)), closeErr, drainErr)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return errors.Join(fmt.Errorf("http server: %w", err), drainErr)
	}
	if drainErr != nil {
		return fmt.Errorf("drain: %w", drainErr)
	}
	logger.Info("shutdown complete", "ms", time.Since(begin).Milliseconds())
	return nil
}
