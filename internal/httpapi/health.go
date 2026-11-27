package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/platform"
)

// Pinger answers whether the database can serve a query; the composition
// root adapts *store.DB with "SELECT 1".
type Pinger interface {
	Ping(ctx context.Context) error
}

// Readiness are the checks of /ready, in the order and with the names of
// the Python release: maintenance, runtime, database, data_directory.
type Readiness struct {
	// Maintenance reports maintenance mode; the probes are skipped then.
	// Optional: this preview has no maintenance mode.
	Maintenance func() bool
	// Stopping reports that shutdown has begun.
	Stopping func() bool
	// Database is pinged on every request (bounded by pingTimeout).
	Database Pinger
	// DataDir is probed with a write, sync and remove; a success is reused
	// for probeTTL, a failure never.
	DataDir string
}

const (
	probeTTL    = 5 * time.Second
	pingTimeout = 2 * time.Second
)

type readiness struct {
	checks Readiness
	log    *slog.Logger
	now    func() time.Time

	mu     sync.Mutex
	passed time.Time
}

func newReadiness(c Readiness, log *slog.Logger) *readiness {
	return &readiness{checks: c, log: log, now: time.Now}
}

// health answers /health: the process serves HTTP.
func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type notReady struct {
	Status string   `json:"status"`
	Failed []string `json:"failed"`
}

// ServeHTTP answers /ready: 200 {"status":"ready"} or 503
// {"status":"not_ready","failed":[…]}. The status codes and bodies are a
// compatibility invariant (orchestrators and the image health check).
func (rd *readiness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if failed := rd.failures(r.Context()); len(failed) > 0 {
		writeJSON(w, http.StatusServiceUnavailable, notReady{Status: "not_ready", Failed: failed})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ReadinessFailures runs the checks of /ready and returns the names of
// those that failed, none when the server is ready (the support report).
func (h *Handler) ReadinessFailures(ctx context.Context) []string { return h.ready.failures(ctx) }

func (rd *readiness) failures(ctx context.Context) []string {
	var failed []string
	maintenance := rd.checks.Maintenance != nil && rd.checks.Maintenance()
	if maintenance {
		failed = append(failed, "maintenance")
	}
	if rd.checks.Stopping == nil || rd.checks.Stopping() {
		failed = append(failed, "runtime")
	}
	if !maintenance {
		if err := rd.ping(ctx); err != nil {
			rd.log.Warn("readiness probe failed", "check", "database", "err", err)
			failed = append(failed, "database")
		}
		if err := rd.probeDataDir(); err != nil {
			rd.log.Warn("readiness probe failed", "check", "data_directory", "err", err)
			failed = append(failed, "data_directory")
		}
	}
	return failed
}

func (rd *readiness) ping(ctx context.Context) error {
	if rd.checks.Database == nil {
		return errNoCheck
	}
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	return rd.checks.Database.Ping(ctx)
}

func (rd *readiness) probeDataDir() error {
	if rd.checks.DataDir == "" {
		return errNoCheck
	}
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if !rd.passed.IsZero() && rd.now().Sub(rd.passed) < probeTTL {
		return nil
	}
	rd.passed = time.Time{}
	if err := platform.ProbeDataDir(rd.checks.DataDir); err != nil {
		return err
	}
	rd.passed = rd.now()
	return nil
}

// errNoCheck fails a readiness check that was not configured: an edge
// without a database or data directory is not ready.
var errNoCheck = errors.New("readiness check not configured")
