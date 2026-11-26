//go:build e2e

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/webssh/internal/e2eseed"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Test-only switches of the end-to-end suite (tests/e2e/README.md). They
// are read here and nowhere else.
const (
	envE2EPort        = "WEBSSH_E2E_PORT"
	envE2ESeed        = "WEBSSH_E2E_SEED"
	envE2EFastHashing = "WEBSSH_E2E_FAST_HASHING"
	defaultE2ESeed    = "tests/e2e/seed.json"
)

func init() { e2eCommand = runE2E }

// runE2E starts the disposable backend of the browser suite:
//
//	WEBSSH_E2E_SERVER_COMMAND='go run -tags e2e ./cmd/webssh e2e'
func runE2E(args []string, _, stderr io.Writer) int {
	if len(args) > 0 {
		return usageError(stderr, "e2e takes no arguments")
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	port, err := e2eseed.ParsePort(os.Getenv(envE2EPort))
	if err != nil {
		log.Error("e2e backend", "error", err)
		return 2
	}
	seed := os.Getenv(envE2ESeed)
	if seed == "" {
		seed = defaultE2ESeed
	}
	opts := e2eseed.Options{
		SeedPath:    seed,
		Port:        port,
		FastHashing: os.Getenv(envE2EFastHashing) == "1",
		Environ:     os.Environ(),
		Log:         log,
	}
	// Playwright stops the server with SIGKILL unless the config asks for
	// a graceful shutdown; an interrupt ends the run and removes the
	// scratch tree.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := e2eseed.Run(ctx, opts, wireE2E); err != nil {
		log.Error("e2e backend", "error", err)
		return 1
	}
	return 0
}

// wireE2E builds the system on the harness's scratch tree and
// configuration. The seed's outbound_ssh_guard replaces the network dialer
// of the SSH client, so no browser case reaches the network.
func wireE2E(ctx context.Context, env e2eseed.Env) (*e2eseed.Backend, error) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var stopping atomic.Bool
	in := bootInput{lookup: env.Lookup, log: log, stopping: stopping.Load, fastHashing: env.FastHashing}
	if env.Dialer != nil {
		in.network = func(p *netpolicy.Policy) client.Network { return guardedNetwork{Policy: p, guard: env.Dialer} }
	}
	sys, err := openSystem(ctx, in)
	if err != nil {
		return nil, err
	}
	return &e2eseed.Backend{
		Stores: e2eStores{sys}.stores(),
		Hooks:  e2eseed.Hooks{OutputFlow: sys.terminal, FixtureSessions: sys.terminal},
		Serve: func(ctx context.Context, ln net.Listener, routes []protocol.Route) error {
			sys.realtime.Mount(routes...)
			srv := &http.Server{Handler: sys.handler(), ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
			httpapi.ConfigureServer(srv)
			done := make(chan error, 1)
			go func() { done <- srv.Serve(ln) }()
			select {
			case err := <-done:
				return err
			case <-ctx.Done():
			}
			stopping.Store(true)
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			drainErr := sys.drain(sctx)
			err := srv.Shutdown(sctx)
			<-done
			return errors.Join(err, drainErr)
		},
		Close: sys.close,
	}, nil
}

// guardedNetwork refuses every outbound connection of the SSH client with
// the seed's text, while the destination checks stay those of the policy.
type guardedNetwork struct {
	*netpolicy.Policy
	guard *e2eseed.GuardDialer
}

func (g guardedNetwork) DialContext(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error) {
	return g.guard.DialContext(ctx, role, network, addr)
}

func (g guardedNetwork) DialRelay(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error) {
	return g.guard.DialContext(ctx, role, network, addr)
}
