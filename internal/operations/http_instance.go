package operations

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// InstanceHTTP serves the instance view and its actions
// (app/operations.py). The edge mounts it behind session, CSRF, origin
// and admin checks; every handler checks the administrator again. Each
// action spends a step-up grant bound to the reference in the path before
// anything else happens, as the Python decorator does.
type InstanceHTTP struct {
	Instance *Instance
	StepUp   StepUp
	Audit    Auditor
	// Enabled is ADMIN_PANEL_ENABLED; off answers 404.
	Enabled bool
	Logger  *slog.Logger
}

// Register adds the routes relative to APPLICATION_ROOT.
func (h *InstanceHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/operations", h.status)
	mux.HandleFunc("GET /admin/api/operations/details", h.details)
	mux.HandleFunc("POST /admin/api/operations/connections/{connection_ref}/disconnect", h.disconnectConnection)
	mux.HandleFunc("POST /admin/api/operations/sessions/{session_ref}/disconnect", h.disconnectSession)
	mux.HandleFunc("POST /admin/api/operations/transfers/{transfer_id}/cancel", h.cancelTransfer)
}

func (h *InstanceHTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h *InstanceHTTP) admin(w http.ResponseWriter, r *http.Request) (principal.Principal, bool) {
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

// action is admin plus the step-up of action bound to target.
func (h *InstanceHTTP) action(w http.ResponseWriter, r *http.Request, action principal.Action, target string) (principal.Principal, bool) {
	p, ok := h.admin(w, r)
	if !ok {
		return p, false
	}
	if err := h.StepUp.Consume(r.Context(), p, action, target, r.Header.Get(StepUpHeader)); err != nil {
		h.fail(w, r, err)
		return p, false
	}
	return p, true
}

func (h *InstanceHTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		h.logger().ErrorContext(r.Context(), "operations request failed", "path", r.URL.Path, "error", err)
	}
	writeJSON(w, status, errorBody(code, message))
}

func (h *InstanceHTTP) view(w http.ResponseWriter, r *http.Request, build func(context.Context) (map[string]any, error)) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	body, err := build(r.Context())
	if err != nil {
		h.fail(w, r, fault.Wrap(fault.StorageError, err, ""))
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func (h *InstanceHTTP) status(w http.ResponseWriter, r *http.Request) {
	h.view(w, r, h.Instance.Status)
}

func (h *InstanceHTTP) details(w http.ResponseWriter, r *http.Request) {
	h.view(w, r, h.Instance.Details)
}

// gone is the answer for a connection, session or transfer that no
// longer exists.
func gone(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusNotFound, map[string]any{"code": "unavailable", "error": message})
}

func unconfirmed(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": string(fault.ActionUnconfirmed), "error": message})
}

func (h *InstanceHTTP) disconnectConnection(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("connection_ref")
	p, ok := h.action(w, r, principal.ActionOperationsConnectionDisconnect, ref)
	if !ok {
		return
	}
	var match *LiveConnection
	if h.Instance.Connections != nil {
		for _, c := range h.Instance.connections() {
			if ConnectionRef(c.ID) == ref {
				match = &c
				break
			}
		}
	}
	if match == nil {
		gone(w, "Connection is no longer active")
		return
	}
	disconnected, err := h.Instance.Connections.Disconnect(r.Context(), match.ID)
	if err != nil {
		h.Audit.Security("ADMIN_CONNECTION_DISCONNECT_FAILED", "admin_id", p.UserID, "target_user_id", match.UserID,
			"error_type", string(fault.CodeOf(err)))
		unconfirmed(w, "Could not confirm disconnection")
		return
	}
	state := "unavailable"
	if disconnected {
		state = "disconnected"
	}
	h.Audit.Security("ADMIN_CONNECTION_DISCONNECT", "admin_id", p.UserID, "target_user_id", match.UserID,
		"connection_ref", ref, "outcome", state)
	writeJSON(w, http.StatusOK, map[string]any{"state": state})
}

func (h *InstanceHTTP) disconnectSession(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("session_ref")
	p, ok := h.action(w, r, principal.ActionOperationsSessionDisconnect, ref)
	if !ok {
		return
	}
	var match *LiveSession
	for _, s := range h.Instance.sessions() {
		if SessionRef(s.ID) == ref {
			match = &s
			break
		}
	}
	if match == nil || match.UserID == 0 {
		gone(w, "Session is no longer active")
		return
	}
	if err := h.Instance.Sessions.Disconnect(r.Context(), match.ID); err != nil {
		h.Audit.Security("ADMIN_SSH_DISCONNECT_FAILED", "admin_id", p.UserID, "target_user_id", match.UserID,
			"session_ref", ref, "error_type", string(fault.CodeOf(err)))
		unconfirmed(w, "Could not confirm disconnection")
		return
	}
	h.Audit.Security("ADMIN_SSH_DISCONNECT", "admin_id", p.UserID, "target_user_id", match.UserID, "session_ref", ref)
	writeJSON(w, http.StatusOK, map[string]any{"state": "disconnected"})
}

func (h *InstanceHTTP) cancelTransfer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("transfer_id")
	p, ok := h.action(w, r, principal.ActionOperationsTransferCancel, id)
	if !ok {
		return
	}
	accepted, state := false, "unavailable"
	if h.Instance.Transfers != nil {
		var err error
		if accepted, state, err = h.Instance.Transfers.Cancel(r.Context(), id); err != nil {
			h.Audit.Security("ADMIN_TRANSFER_CANCEL_FAILED", "admin_id", p.UserID, "transfer_id", id,
				"error_type", string(fault.CodeOf(err)))
			unconfirmed(w, "Could not confirm cancellation")
			return
		}
	}
	h.Audit.Security("ADMIN_TRANSFER_CANCEL", "admin_id", p.UserID, "transfer_id", id, "outcome", state)
	status := http.StatusOK
	if state == "unavailable" {
		status = http.StatusNotFound
	}
	writeJSON(w, status, map[string]any{"accepted": accepted, "state": state})
}
