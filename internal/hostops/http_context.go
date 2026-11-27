package hostops

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"

	"github.com/bifrost0x/webssh/internal/principal"
)

// maxContextBody is the body limit of request_limits.py for this route.
const maxContextBody = 1 << 20

// ContextHTTP serves GET and PUT /api/profiles/{profile_id}/context for
// the signed-in user. The edge mounts it behind session, CSRF and origin
// checks.
type ContextHTTP struct {
	Contexts *Contexts
	Logger   *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *ContextHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/profiles/{profile_id}/context", h.serve)
	mux.HandleFunc("PUT /api/profiles/{profile_id}/context", h.serve)
}

// contextJSON is the wire form of the Python release.
type contextJSON struct {
	CommandSets []string `json:"command_sets"`
	Directories []string `json:"directories"`
	Notes       string   `json:"notes"`
	Revision    int64    `json:"revision"`
}

const contextErrorText = "Host context could not be saved or loaded."

var contextStatus = map[string]int{"not_found": http.StatusNotFound, "conflict": http.StatusConflict, "quota": http.StatusRequestEntityTooLarge}

func (h *ContextHTTP) serve(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		writeContextJSON(w, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
		return
	}
	profileID := r.PathValue("profile_id")
	var hc HostContext
	if r.Method == http.MethodPut {
		var content Content
		var revision int64
		if content, revision, err = readContext(w, r); err == nil {
			hc, err = h.Contexts.Write(r.Context(), p.UserID, profileID, content, revision)
		}
	} else {
		hc, err = h.Contexts.Read(r.Context(), p.UserID, profileID)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeContextJSON(w, http.StatusOK, contextJSON{CommandSets: nonNil(hc.CommandSets), Directories: nonNil(hc.Directories), Notes: hc.Notes, Revision: hc.Revision})
}

func (h *ContextHTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	ce, ok := errors.AsType[*ContextError](err)
	if !ok {
		h.logger().ErrorContext(r.Context(), "host context request failed", "error", err)
		writeContextJSON(w, http.StatusInternalServerError, map[string]string{"error": contextErrorText, "code": "storage"})
		return
	}
	status, known := contextStatus[ce.Code]
	if !known {
		status = http.StatusBadRequest
	}
	writeContextJSON(w, status, map[string]string{"error": contextErrorText, "code": ce.Code})
}

func (h *ContextHTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// readContext accepts what the Python route accepted: a JSON object with
// exactly revision, notes, directories and command_sets; notes a string,
// both lists of strings, revision an integer (not a boolean, not a
// float). Everything else is invalid.
func readContext(w http.ResponseWriter, r *http.Request) (Content, int64, error) {
	invalid := contextError("invalid")
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !hasJSONSuffix(mediaType)) {
		return Content{}, 0, invalid
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxContextBody))
	if err != nil {
		return Content{}, 0, invalid
	}
	var members map[string]jsontext.Value
	if json.Unmarshal(raw, &members) != nil || len(members) != 4 {
		return Content{}, 0, invalid
	}
	var c Content
	var revision int64
	for name, v := range members {
		var ok bool
		switch name {
		case "notes":
			ok = v.Kind() == '"' && json.Unmarshal(v, &c.Notes) == nil
		case "directories":
			ok = v.Kind() == '[' && json.Unmarshal(v, &c.Directories) == nil
		case "command_sets":
			ok = v.Kind() == '[' && json.Unmarshal(v, &c.CommandSets) == nil
		case "revision":
			revision, ok = integer(v)
		}
		if !ok {
			return Content{}, 0, invalid
		}
	}
	return c, revision, nil
}

// integer reads a JSON integer token. An integer beyond int64 is no
// stored revision, so it is reported as -1, which always conflicts.
func integer(v jsontext.Value) (int64, bool) {
	if v.Kind() != '0' {
		return 0, false
	}
	s := string(v)
	for i := range len(s) {
		if c := s[i]; c == '.' || c == 'e' || c == 'E' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1, true
	}
	return n, true
}

func hasJSONSuffix(mediaType string) bool {
	const suffix = "+json"
	return len(mediaType) > len(suffix) && mediaType[len(mediaType)-len(suffix):] == suffix
}

func writeContextJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}
