//go:build e2e

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/bifrost0x/webssh/internal/e2eseed"
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

// errNotWired is returned until the composition root can build the HTTP
// server and the stores; the start fails instead of serving a partial
// backend.
var errNotWired = errors.New("this build has no HTTP server and stores to wire yet")

func wireE2E(context.Context, e2eseed.Env) (*e2eseed.Backend, error) {
	return nil, errNotWired
}
