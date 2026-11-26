package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/bifrost0x/webssh/internal/platform"
)

// buildProbeApplication serves only /health and /ready on the prepared
// data directory. The lifecycle tests use it in place of the system, whose
// probes internal/httpapi tests.
func buildProbeApplication(_ context.Context, state *runtimeState) (application, error) {
	root, err := platform.PrepareDataDir(state.dataDir)
	if err != nil {
		return application{}, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		if state.Stopping() || platform.ProbeDataDir(root) != nil {
			writeTestJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready"})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	})
	return application{handler: mux}, nil
}

func writeTestJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
