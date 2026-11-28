package vault

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

// maxCredentialBody bounds a request body: a password of 4096 bytes with
// its target and resource in JSON escapes fits many times over.
const maxCredentialBody = 256 << 10

// CredentialsHTTP serves the saved-password routes of the page
// (credential_routes.py). The edge mounts it behind session, CSRF and
// origin checks; every route also needs HTTPS.
type CredentialsHTTP struct {
	Service *Service
	// HTTPS reports whether the browser reached WebSSH over HTTPS
	// (httpapi.ReachedOverHTTPS).
	HTTPS func(*http.Request) bool
	// Index is the URL of the workspace page for a request.
	Index  func(*http.Request) string
	Logger *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT. The
// passphrase vault routes (/api/credentials/apply, /api/credentials/lock,
// /api/automation/vault/*) are not built (D-06).
func (h *CredentialsHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /credentials", h.page)
	mux.HandleFunc("GET /api/credentials/state", h.state)
	mux.HandleFunc("POST /api/credentials/intents", h.intents)
	mux.HandleFunc("POST /api/credentials", h.native(MethodCreate))
	mux.HandleFunc("PATCH /api/credentials/{rid}", h.native(MethodUpdate))
	mux.HandleFunc("DELETE /api/credentials/{rid}", h.native(MethodDelete))
	mux.HandleFunc("POST /api/credentials/assign", h.native(MethodAssign))
	mux.HandleFunc("POST /api/credentials/import-legacy", h.native(MethodImport))
	mux.HandleFunc("POST /api/credentials/authorize-target", h.native(MethodAuthorizeTarget))
	mux.HandleFunc("POST /api/credentials/create-for-resource", h.native(MethodCreateForResource))
}

func (h *CredentialsHTTP) page(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, h.Index(r)+"#passwords", http.StatusFound)
}

func (h *CredentialsHTTP) secure(r *http.Request) error {
	if h.HTTPS == nil || !h.HTTPS(r) {
		return fault.New(fault.HTTPSRequired, "")
	}
	return nil
}

func (h *CredentialsHTTP) state(w http.ResponseWriter, r *http.Request) {
	if err := h.secure(r); err != nil {
		h.fail(w, r, err)
		return
	}
	out, err := h.Service.State(r.Context())
	h.reply(w, r, out, err)
}

func (h *CredentialsHTTP) intents(w http.ResponseWriter, r *http.Request) {
	body, err := h.body(w, r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out, err := h.Service.Prepare(r.Context(), body)
	h.reply(w, r, out, err)
}

func (h *CredentialsHTTP) native(method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := h.body(w, r)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		out, err := h.Service.Apply(r.Context(), method, r.PathValue("rid"), body, r.Header.Get(StepUpHeader))
		h.reply(w, r, out, err)
	}
}

// body checks HTTPS and reads a JSON object as Flask's get_json() did:
// duplicate members keep the last value. Anything else is invalid_request.
func (h *CredentialsHTTP) body(w http.ResponseWriter, r *http.Request) (jsontext.Value, error) {
	if err := h.secure(r); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCredentialBody))
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

// pythonStatus is the status map of credential_routes.py failure().
var pythonStatus = map[fault.Code]int{
	fault.AuthenticationNeeded: 401, fault.HTTPSRequired: 403, fault.StepUpRequired: 403, fault.Busy: 429,
	fault.NotFound: 404, fault.InvalidIntent: 409, fault.PreviewChanged: 409, fault.VaultLocked: 423,
	fault.Unavailable: 503, fault.CredentialsDisabled: 403, fault.CredentialInUse: 409,
	fault.DuplicateName: 409, // new in 3.4: names are unique (U100)
}

type credentialError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// fail answers with the code and the generic text of the Python release;
// the cause of a storage failure is logged, never sent.
func (h *CredentialsHTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, _ := fault.Status(err)
	if s, ok := pythonStatus[code]; ok {
		status = s
	} else if status < 500 && code != fault.TooLarge && code != fault.Forbidden && code != fault.StepUpFailed {
		status = http.StatusBadRequest
	}
	if status >= 500 {
		logger := h.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.ErrorContext(r.Context(), "credential request failed", "code", code, "error", err)
	}
	text := "Credential request could not be completed."
	if code == fault.ValidationError || code == fault.DuplicateName {
		// The fixed texts of the resource stores (an invalid host, a taken
		// name) when a resource is saved with its password.
		_, _, text = fault.Status(err)
	}
	writeCredentialJSON(w, status, credentialError{Error: text, Code: string(code)})
}

func (h *CredentialsHTTP) reply(w http.ResponseWriter, r *http.Request, out jsontext.Value, err error) {
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeCredentialJSON(w, http.StatusOK, out)
}

func writeCredentialJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}
