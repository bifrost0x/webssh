package httpapi

import (
	"encoding/json/v2"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
)

// wantsJSON reports whether a failure is answered as JSON rather than as
// a page, with the rule of the Python release (_wants_json): API paths,
// JSON request bodies and clients that prefer JSON.
func wantsJSON(r *http.Request) bool {
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/admin/api/") || strings.HasPrefix(p, "/auth/api/") {
		return true
	}
	if ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && (ct == "application/json" || strings.HasSuffix(ct, "+json")) {
		return true
	}
	return prefersJSON(r.Header.Get("Accept"))
}

// prefersJSON reports whether application/json has the highest quality
// in an Accept header, as Werkzeug's accept_mimetypes.best does.
func prefersJSON(accept string) bool {
	best, bestQ := "", -1.0
	for part := range strings.SplitSeq(accept, ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		q := 1.0
		if v, ok := params["q"]; ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		if q > bestQ {
			best, bestQ = mt, q
		}
	}
	return best == "application/json" && bestQ > 0
}

// writeJSON sends a JSON body. The client may be gone; there is nobody
// left to report a write failure to.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}

// errorBody is the JSON shape the frontend expects for failures.
type errorBody struct {
	Success bool       `json:"success"`
	Code    fault.Code `json:"code"`
	Error   string     `json:"error"`
}

// writeFault answers err as JSON through fault.Status. The cause of an
// unclassified error is logged, never sent.
func writeFault(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal {
		log.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	}
	if retry := fault.RetryAfter(err); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int((retry+999_999_999)/1_000_000_000)))
	}
	writeJSON(w, status, errorBody{Code: code, Error: message})
}

// errorPageData returns the page data of the error page for a request.
type errorPageData func(r *http.Request) PageData

// errorKind is the kind the error template shows.
type errorKind string

const (
	kindFormExpired    errorKind = "form_expired"
	kindCookieRejected errorKind = "cookie_rejected"
	kindForbidden      errorKind = "forbidden"
	kindNotFound       errorKind = "not_found"
)

// fail answers a refused request: JSON for API clients, otherwise the
// error page of kind when the edge has a renderer, otherwise (and for an
// empty kind) plain text.
// actionURL is the link the page offers; "" means the start page.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error, kind errorKind, actionURL string) {
	if wantsJSON(r) {
		writeFault(w, r, h.log, err)
		return
	}
	status, _, message := fault.Status(err)
	if h.renderer == nil || kind == "" {
		writePlain(w, status, message)
		return
	}
	data := PageData{Theme: "glass"}
	if h.pageData != nil {
		data = h.pageData(r)
	}
	base := BasePath(r)
	data.BasePath = base
	data.URLPrefix = h.cfg.ApplicationRoot
	data.Status = status
	data.Kind = string(kind)
	data.Detail = ""
	data.ActionURL = base + "/"
	if actionURL != "" {
		data.ActionURL = base + actionURL
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf strings.Builder
	if rerr := h.renderer.Render(&buf, PageError, data); rerr != nil {
		h.log.ErrorContext(r.Context(), "render error page", "err", rerr)
		writePlain(w, status, message)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(buf.String()))
}

func writePlain(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message + "\n"))
}
