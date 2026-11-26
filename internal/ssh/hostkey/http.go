package hostkey

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"log/slog"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

// HTTP serves the host-key routes of a signed-in user. The edge mounts it
// behind session, CSRF and origin checks; the principal comes from the
// request context.
type HTTP struct {
	Store   *Store
	Targets Targets
	StepUp  StepUp
	// Enabled is HOST_KEY_MANAGEMENT_ENABLED; off answers 404 everywhere.
	Enabled bool
	Logger  *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/host-keys", h.serve(h.list))
	mux.HandleFunc("GET /api/host-keys/effective", h.serve(h.effective))
	mux.HandleFunc("GET /api/host-keys/{id}/deletion-impact", h.serve(h.impact))
	mux.HandleFunc("DELETE /api/host-keys/{id}", h.serve(h.delete))
}

type handler func(ctx context.Context, p principal.Principal, r *http.Request) (any, error)

func (h *HTTP) serve(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.Enabled {
			http.NotFound(w, r)
			return
		}
		p, err := principal.Require(r.Context())
		if err == nil {
			var body any
			if body, err = fn(r.Context(), p, r); err == nil {
				writeJSON(w, http.StatusOK, body)
				return
			}
		}
		status, code, message := fault.Status(err)
		if code == fault.Internal || code == fault.StorageError {
			h.logger().ErrorContext(r.Context(), "host key request failed", "path", r.URL.Path, "error", err)
		}
		writeJSON(w, status, errorBody{Success: false, Code: string(code), Error: message})
	}
}

func (h *HTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

type errorBody struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Error   string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}

type hostJSON struct {
	Host string         `json:"host"`
	Port jsontext.Value `json:"port"`
}

type entryJSON struct {
	ID          string         `json:"id"`
	Host        string         `json:"host"`
	Port        jsontext.Value `json:"port"`
	Hosts       []hostJSON     `json:"hosts"`
	Marker      *string        `json:"marker"`
	Algorithm   string         `json:"algorithm"`
	Fingerprint string         `json:"fingerprint"`
	Scope       string         `json:"scope"`
	OwnerID     int64          `json:"owner_id"`
	FirstSeen   string         `json:"first_seen"`
	LastSeen    string         `json:"last_seen"`
}

type keyJSON struct {
	Scope       string `json:"scope"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
}

type targetJSON struct {
	ID   string    `json:"id"`
	Name string    `json:"name"`
	Kind string    `json:"kind"`
	Host string    `json:"host"`
	Port int       `json:"port"`
	Keys []keyJSON `json:"keys"`
}

func portJSON(port int) jsontext.Value {
	if port == 0 {
		return jsontext.Value("null")
	}
	v, _ := json.Marshal(port)
	return v
}

func (h *HTTP) list(ctx context.Context, p principal.Principal, _ *http.Request) (any, error) {
	entries, err := h.Store.List(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]entryJSON, 0, len(entries))
	for _, e := range entries {
		j := entryJSON{
			ID: e.ID, Algorithm: e.Algorithm, Fingerprint: e.Fingerprint, Scope: string(ScopeUser),
			OwnerID: e.Owner, FirstSeen: pythonISOTime(e.Modified), LastSeen: pythonISOTime(e.Modified),
			Hosts: make([]hostJSON, 0, len(e.Hosts)),
		}
		if e.Marker != MarkerNone {
			m := string(e.Marker)
			j.Marker = &m
		}
		for _, ref := range e.Hosts {
			j.Hosts = append(j.Hosts, hostJSON{Host: ref.Host, Port: portJSON(ref.Port)})
		}
		j.Host, j.Port = j.Hosts[0].Host, j.Hosts[0].Port
		out = append(out, j)
	}
	return map[string]any{"entries": out}, nil
}

func targetsJSON(reports []TargetReport) []targetJSON {
	out := make([]targetJSON, 0, len(reports))
	for _, r := range reports {
		t := targetJSON{ID: r.ID, Name: r.Name, Kind: r.Kind, Host: r.Host, Port: r.Port, Keys: make([]keyJSON, 0, len(r.Keys))}
		for _, k := range r.Keys {
			t.Keys = append(t.Keys, keyJSON{Scope: string(k.Scope), Algorithm: k.Algorithm, Fingerprint: k.Fingerprint, Status: k.Status})
		}
		out = append(out, t)
	}
	return out
}

func (h *HTTP) effective(ctx context.Context, p principal.Principal, _ *http.Request) (any, error) {
	targets, err := h.Targets.SSHTargets(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	reports, err := h.Store.Effective(ctx, p.UserID, targets)
	if err != nil {
		return nil, err
	}
	return map[string]any{"targets": targetsJSON(reports)}, nil
}

func (h *HTTP) impact(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	targets, err := h.Targets.SSHTargets(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	impact, err := h.Store.DeletionImpact(ctx, p.UserID, r.PathValue("id"), targets)
	if err != nil {
		return nil, err
	}
	return map[string]any{"revision": impact.Revision, "targets": targetsJSON(impact.Targets), "unresolved": impact.Unresolved}, nil
}

// delete removes one of the user's own entries. It needs a step-up grant
// for host_key.delete bound to the entry id. The entry and the previewed
// revision are checked before the grant is spent, and again when writing.
func (h *HTTP) delete(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	id := r.PathValue("id")
	revision := r.Header.Get("If-Match")
	checkRevision := revision != ""
	impact, err := h.Store.DeletionImpact(ctx, p.UserID, id, nil)
	switch {
	case err != nil:
		return nil, err
	case checkRevision && (!validID(revision) || revision != impact.Revision):
		return nil, errTrustChanged
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionHostKeyDelete, id, r.Header.Get(StepUpHeader)); err != nil {
		return nil, err
	}
	if err := h.Store.Delete(ctx, p.UserID, id, revision, checkRevision); err != nil {
		return nil, err
	}
	h.logger().InfoContext(ctx, "SSH_HOST_KEY_DELETED", "user", p.Username, "entry_id", id)
	return map[string]any{"ok": true}, nil
}
