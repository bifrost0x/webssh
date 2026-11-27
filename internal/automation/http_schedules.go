package automation

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// maxScheduleBody bounds a request body: 100 target ids and group names
// of 128 bytes each in JSON escapes fit many times over.
const maxScheduleBody = 256 << 10

// SchedulesHTTP serves the schedule routes of the automation page
// (app/automation_routes.py). The edge mounts it behind session, CSRF and
// origin checks; every route also needs HTTPS (Secure), and the routes
// that review or approve need automation to be on.
type SchedulesHTTP struct {
	Schedules *Schedules
	// Secure reports whether the request may use automation: it reached
	// WebSSH over HTTPS, or the documented loopback exception applies
	// (AUTOMATION_ALLOW_INSECURE_LOOPBACK).
	Secure func(*http.Request) bool
	Logger *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *SchedulesHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/automation/schedules", h.list)
	mux.HandleFunc("POST /api/automation/schedules/preview", h.preview)
	mux.HandleFunc("POST /api/automation/schedules", h.approve)
	mux.HandleFunc("POST /api/automation/schedules/{schedule_id}/pause", h.pause)
	mux.HandleFunc("POST /api/automation/schedules/{schedule_id}/preview-run", h.previewRun)
	mux.HandleFunc("DELETE /api/automation/schedules/{schedule_id}", h.remove)
}

// begin returns the principal of a request that passed the HTTPS check
// and, with enabled, the automation switch and the runtime check.
func (h *SchedulesHTTP) begin(r *http.Request, enabled bool) (principal.Principal, error) {
	p, err := principal.Require(r.Context())
	if err != nil {
		return p, fault.New(fault.AuthenticationNeeded, "")
	}
	if enabled {
		if _, err := h.Schedules.policy(r.Context()); err != nil {
			return p, err
		}
	}
	if h.Secure == nil || !h.Secure(r) {
		return p, fault.New(fault.HTTPSRequired, "")
	}
	if enabled && h.Schedules.o.Draining() {
		return p, fault.New(fault.Unavailable, "")
	}
	return p, nil
}

func (h *SchedulesHTTP) list(w http.ResponseWriter, r *http.Request) {
	p, err := h.begin(r, false)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items, err := h.Schedules.List(r.Context(), p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.ok(w, pyjson.Object([]pyjson.Member{{Name: "schedules", Value: pyjson.Array(items)}}))
}

func (h *SchedulesHTTP) preview(w http.ResponseWriter, r *http.Request) {
	p, err := h.begin(r, true)
	var body, out jsontext.Value
	if err == nil {
		body, err = readBody(w, r)
	}
	if err == nil {
		out, err = h.Schedules.Prepare(r.Context(), p, body)
	}
	h.reply(w, r, out, err)
}

func (h *SchedulesHTTP) approve(w http.ResponseWriter, r *http.Request) {
	p, err := h.begin(r, true)
	var body, out jsontext.Value
	if err == nil {
		body, err = readBody(w, r)
	}
	if err == nil {
		token, _ := jsonText(field(body, "intent"))
		confirmation, okC := jsonText(field(body, "confirmation"))
		if !okC {
			confirmation = "\x00" // not a string: never the expected count
		}
		out, err = h.Schedules.Approve(r.Context(), p, token, confirmation, r.Header.Get(StepUpHeader))
	}
	if err == nil {
		out = pyjson.Object([]pyjson.Member{{Name: "schedule", Value: out}})
	}
	h.reply(w, r, out, err)
}

func (h *SchedulesHTTP) pause(w http.ResponseWriter, r *http.Request) {
	p, err := h.begin(r, false)
	var out jsontext.Value
	if err == nil {
		out, err = h.Schedules.Pause(r.Context(), p.UserID, r.PathValue("schedule_id"))
	}
	if err == nil {
		out = pyjson.Object([]pyjson.Member{{Name: "schedule", Value: out}})
	}
	h.reply(w, r, out, err)
}

func (h *SchedulesHTTP) previewRun(w http.ResponseWriter, r *http.Request) {
	p, err := h.begin(r, true)
	var out jsontext.Value
	if err == nil {
		out, err = h.Schedules.PrepareRun(r.Context(), p, r.PathValue("schedule_id"))
	}
	h.reply(w, r, out, err)
}

func (h *SchedulesHTTP) remove(w http.ResponseWriter, r *http.Request) {
	p, err := h.begin(r, false)
	if err == nil {
		err = h.Schedules.Delete(r.Context(), p.UserID, r.PathValue("schedule_id"))
	}
	h.reply(w, r, jsontext.Value(`{"deleted":true}`), err)
}

// readBody reads a JSON object as Flask's get_json(silent=True) did:
// anything else is invalid_request.
func readBody(w http.ResponseWriter, r *http.Request) (jsontext.Value, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxScheduleBody))
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			return nil, fault.New(fault.TooLarge, "")
		}
		return nil, fault.New(fault.InvalidRequest, "")
	}
	v, _, err := pyjson.Load(raw)
	if err != nil || v.Kind() != '{' {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	return v, nil
}

// automationStatus is the status map of failure() in
// app/automation_routes.py; every other code of a request is 400.
var automationStatus = map[fault.Code]int{
	fault.AuthenticationNeeded: 401, fault.AutomationDisabled: 403, fault.HTTPSRequired: 403,
	fault.StepUpRequired: 403, fault.Busy: 429, fault.NotFound: 404, fault.InvalidIntent: 409,
	fault.PreviewChanged: 409, fault.HostKeyRequired: 409, fault.VaultLocked: 423, fault.Unavailable: 503, fault.CredentialsDisabled: 403,
}

// hostsError is implemented by the review failure that names the saved
// hosts without a verified host key (host_key_required).
type hostsError interface {
	error
	Hosts() []string
}

func (h *SchedulesHTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, _ := fault.Status(err)
	body := []pyjson.Member{{Name: "error", Value: pyjson.String("Automation request could not be completed.")}}
	switch s, known := automationStatus[code]; {
	case code == fault.StorageError || status >= 500 && !known:
		logger := h.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.ErrorContext(r.Context(), "schedule request failed", "code", code, "error", err)
		status, code = http.StatusServiceUnavailable, "storage_unavailable"
		body[0].Value = pyjson.String("Automation storage is unavailable.")
	case known:
		status = s
	case code != fault.TooLarge:
		status = http.StatusBadRequest
	}
	body = append(body, pyjson.Member{Name: "code", Value: pyjson.String(string(code))})
	if he, ok := errors.AsType[hostsError](err); ok && len(he.Hosts()) > 0 {
		hosts := make([]jsontext.Value, 0, len(he.Hosts()))
		for _, name := range he.Hosts() {
			hosts = append(hosts, pyjson.String(name))
		}
		body = append(body, pyjson.Member{Name: "hosts", Value: pyjson.Array(hosts)})
	}
	writeJSON(w, status, pyjson.Object(body))
}

func (h *SchedulesHTTP) reply(w http.ResponseWriter, r *http.Request, out jsontext.Value, err error) {
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.ok(w, out)
}

func (h *SchedulesHTTP) ok(w http.ResponseWriter, out jsontext.Value) {
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, body jsontext.Value) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}
