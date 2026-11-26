package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/platform"
)

// probeTTL is how long a successful data directory probe is reused, so a
// flood of readiness requests does not turn into a flood of fsyncs. The
// Python application uses the same interval.
const probeTTL = 5 * time.Second

// buildProbeApplication serves only /health and /ready. It stands in until
// the HTTP server of internal/httpapi is wired here, which then answers the
// same two routes with the same bodies.
func buildProbeApplication(state *runtimeState) (application, error) {
	probe := &cachedProbe{dir: state.dataDir, ttl: probeTTL, now: time.Now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		var failed []string
		if state.Stopping() {
			failed = append(failed, "runtime")
		} else if err := probe.check(); err != nil {
			state.logger.Warn("readiness probe failed", "check", "data_directory", "err", err)
			failed = append(failed, "data_directory")
		}
		if len(failed) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "failed": failed})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	})
	return application{handler: mux}, nil
}

// cachedProbe runs platform.ProbeDataDir at most once per ttl while it
// succeeds; a failure is never cached.
type cachedProbe struct {
	dir string
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	passed time.Time
}

func (p *cachedProbe) check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.passed.IsZero() && p.now().Sub(p.passed) < p.ttl {
		return nil
	}
	p.passed = time.Time{}
	if err := platform.ProbeDataDir(p.dir); err != nil {
		return err
	}
	p.passed = p.now()
	return nil
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	// The client may be gone; there is nobody left to report it to.
	_ = json.NewEncoder(w).Encode(body)
}
