package hostops

import (
	"context"
	json "encoding/json/v2"
	"log/slog"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// OverviewHTTP serves the overview data of a signed-in account. The edge
// mounts it behind session, CSRF and origin checks; the principal comes
// from the request context.
//
// GET /api/overview/reachability returns the last check of Reach without
// contacting any host; without Reach it answers "no result" with available
// false.
type OverviewHTTP struct {
	Inventory Inventory
	Trust     HostTrust
	Reach     *Reachability
	Logger    *slog.Logger
	now       func() time.Time
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *OverviewHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/overview/status", h.serve(h.status))
	mux.HandleFunc("GET /api/overview/reachability", h.serve(h.reachability))
}

type statusResponse struct {
	Hosts       []Readiness `json:"hosts"`
	GeneratedAt float64     `json:"generated_at"`
	// Available names the overview parts this release computes on the
	// server; the page shows the others as not available.
	Available map[string]bool `json:"available"`
}

func (h *OverviewHTTP) status(ctx context.Context, p principal.Principal) (any, error) {
	inv, err := h.Inventory.OverviewInventory(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	rows, err := readiness(ctx, p.UserID, inv, h.Trust)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if h.now != nil {
		now = h.now
	}
	return statusResponse{
		Hosts:       rows,
		GeneratedAt: float64(now().UnixMicro()) / 1e6,
		Available:   map[string]bool{"readiness": true, "automation": true, "reachability": h.Reach != nil},
	}, nil
}

func (h *OverviewHTTP) reachability(ctx context.Context, p principal.Principal) (any, error) {
	if h.Reach == nil {
		return map[string]any{"results": nil, "available": false}, nil
	}
	return h.Reach.Last(ctx, p)
}

func (h *OverviewHTTP) serve(fn func(context.Context, principal.Principal) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := principal.Require(r.Context())
		if err == nil {
			var body any
			if body, err = fn(r.Context(), p); err == nil {
				writeOverviewJSON(w, http.StatusOK, body)
				return
			}
		}
		status, code, message := fault.Status(err)
		if code == fault.Internal || code == fault.StorageError || code == fault.Unavailable {
			h.logger().ErrorContext(r.Context(), "overview request failed", "path", r.URL.Path, "error", err)
		}
		writeOverviewJSON(w, status, map[string]any{"success": false, "code": string(code), "error": message})
	}
}

func (h *OverviewHTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func writeOverviewJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body, json.Deterministic(true))
}
