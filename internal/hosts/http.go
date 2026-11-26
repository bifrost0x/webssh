package hosts

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// maxPresetBody bounds a PUT of the workspace presets; twelve presets of
// four hosts need a few kilobytes.
const maxPresetBody = 64 << 10

// HTTP serves the workspace presets of the signed-in user. The edge mounts
// it behind session, CSRF and origin checks; the principal comes from the
// request context.
type HTTP struct {
	Service *Service
	Logger  *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/account/workspace-presets", h.presets)
	mux.HandleFunc("PUT /api/account/workspace-presets", h.presets)
}

type presetsBody struct {
	Presets jsontext.Value `json:"presets"`
}

func (h *HTTP) presets(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var out jsontext.Value
	if r.Method == http.MethodPut {
		var body presetsBody
		if body, err = readPresets(w, r); err == nil {
			out, err = h.Service.SaveWorkspacePresets(r.Context(), p.UserID, body.Presets)
		}
	} else {
		out, err = h.Service.WorkspacePresets(r.Context(), p.UserID)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, presetsBody{Presets: out})
}

// readPresets accepts what Flask's get_json() accepted for this route, a
// JSON body {"presets": …}, decoded strictly: duplicate or unknown members
// are refused.
func readPresets(w http.ResponseWriter, r *http.Request) (presetsBody, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !hasJSONSuffix(mediaType)) {
		return presetsBody{}, errInvalidPresets
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPresetBody))
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			return presetsBody{}, fault.New(fault.TooLarge, "")
		}
		return presetsBody{}, errInvalidPresets
	}
	var body presetsBody
	if json.Unmarshal(raw, &body, json.RejectUnknownMembers(true)) != nil || len(body.Presets) == 0 {
		return presetsBody{}, errInvalidPresets
	}
	return body, nil
}

func hasJSONSuffix(mediaType string) bool {
	const suffix = "+json"
	return len(mediaType) > len(suffix) && mediaType[len(mediaType)-len(suffix):] == suffix
}

type errorBody struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Error   string `json:"error"`
}

func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		h.logger().ErrorContext(r.Context(), "workspace presets request failed", "error", err)
	}
	writeJSON(w, status, errorBody{Success: false, Code: string(code), Error: message})
}

func (h *HTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}
