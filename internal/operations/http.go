package operations

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

// HTTP serves the security feature gates of the admin panel. The edge
// mounts it behind session, CSRF, origin and admin checks; the handlers
// check the administrator again.
type HTTP struct {
	Gates     *Gates
	Inventory Inventory
	StepUp    StepUp
	MAC       MAC
	// Enabled is ADMIN_PANEL_ENABLED; off answers 404.
	Enabled bool
	Logger  *slog.Logger
	Now     func() time.Time
}

// Register adds the routes relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/security-features", h.list)
	mux.HandleFunc("GET /admin/api/security-features/{feature}/impact", h.impact)
	mux.HandleFunc("POST /admin/api/security-features/{feature}", h.set)
}

func (h *HTTP) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *HTTP) admin(w http.ResponseWriter, r *http.Request) (principal.Principal, bool) {
	if !h.Enabled {
		http.NotFound(w, r)
		return principal.Principal{}, false
	}
	p, err := principal.RequireAdmin(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return p, false
	}
	return p, true
}

func (h *HTTP) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	all, err := h.Gates.All(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"features": all})
}

func (h *HTTP) impact(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	name, err := normalize(r.PathValue("feature"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	digest, im, err := h.Gates.snapshot(r.Context(), h.Inventory, name)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"impact": im, "approval": approval(h.MAC, name, p, h.now(), digest)})
}

type setJSON struct {
	Enabled         jsontext.Value `json:"enabled"`
	ConfirmFallback jsontext.Value `json:"confirm_session_fallback"`
	ImpactApproval  jsontext.Value `json:"impact_approval"`
}

// set needs the step-up security_feature.update bound to the feature name
// from the URL; the grant is spent before the body is read, as in the
// Python release. Turning an active feature off needs an explicit
// confirmation and a fresh impact approval of the same session.
func (h *HTTP) set(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	raw := r.PathValue("feature")
	if err := h.StepUp.Consume(r.Context(), p, principal.ActionSecurityFeatureUpdate, raw, r.Header.Get(StepUpHeader)); err != nil {
		h.fail(w, r, err)
		return
	}
	name, err := normalize(raw)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	var in setJSON
	if json.Unmarshal(body, &in) != nil || (in.Enabled.Kind() != 't' && in.Enabled.Kind() != 'f') {
		writeJSON(w, http.StatusBadRequest, errorBody(fault.InvalidValue, "enabled must be a boolean"))
		return
	}
	enabled := in.Enabled.Kind() == 't'
	cur, err := h.Gates.Status(r.Context(), name)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if cur.Active && !enabled {
		if in.ConfirmFallback.Kind() != 't' {
			h.Gates.logger(h.Logger).WarnContext(r.Context(), "Security feature change needs fallback confirmation", "admin", p.Username, "feature", name)
			writeJSON(w, http.StatusConflict, map[string]any{
				"success": false, "error": "Explicit confirmation is required", "code": "session_fallback_confirmation_required",
				"message": "Existing browser, SSH, and tmux sessions will not be terminated. New logins and factor ceremonies will follow the disabled rule immediately.",
				"feature": cur,
			})
			return
		}
		var token string
		_ = json.Unmarshal(in.ImpactApproval, &token)
		digest, _, err := h.Gates.snapshot(r.Context(), h.Inventory, name)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if !approvalValid(h.MAC, token, name, p, h.now(), digest) {
			writeJSON(w, http.StatusConflict, map[string]any{"success": false,
				"error": "Account configuration changed or approval expired. Review the impact again.", "code": "feature_impact_changed"})
			return
		}
	}
	s, err := h.Gates.set(r.Context(), p, name, enabled)
	var unavailable errUnavailable
	if errors.As(err, &unavailable) {
		reason := ""
		if unavailable.status.Reason != nil {
			reason = *unavailable.status.Reason
		}
		writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": string(fault.Conflict), "error": reason, "feature": unavailable.status})
		return
	}
	if err != nil {
		h.fail(w, r, fault.Wrap(fault.StorageError, err, ""))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"feature": s})
}

func (g *Gates) logger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}

func errorBody(code fault.Code, message string) map[string]any {
	return map[string]any{"success": false, "code": string(code), "error": message}
}

func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		h.Gates.logger(h.Logger).ErrorContext(r.Context(), "feature gate request failed", "path", r.URL.Path, "error", err)
	}
	writeJSON(w, status, errorBody(code, message))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}
