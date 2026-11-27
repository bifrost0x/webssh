package audit

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

// StepUp consumes a step-up grant for one action on one target (provided
// by internal/auth/stepup); it fails with fault.StepUpRequired when the
// grant does not match.
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// RetentionStore keeps the administrator's audit_backup_count (provided
// by internal/settings).
type RetentionStore interface {
	SetAuditBackupCount(ctx context.Context, n int) error
}

// HTTP serves the audit view, the export and the retention setting of
// the administration (app/audit_export.py, admin_audit). The edge mounts
// it behind session, CSRF, origin and admin checks; the handlers check
// the administrator again.
type HTTP struct {
	Logger    *Logger
	Retention RetentionStore
	StepUp    StepUp
	// Enabled is AUDIT_EXPORT_ENABLED; off answers 404 on every route.
	Enabled bool
	Log     *slog.Logger
}

// Register adds the routes relative to APPLICATION_ROOT. GET also
// answers HEAD, as Flask does.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/audit", h.view)
	mux.HandleFunc("GET /admin/api/audit/export", h.export)
	mux.HandleFunc("POST /admin/api/audit/retention", h.retention)
}

func (h *HTTP) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *HTTP) admin(w http.ResponseWriter, r *http.Request) (principal.Principal, bool) {
	p, err := principal.RequireAdmin(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return p, false
	}
	return p, true
}

func (h *HTTP) view(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	if !h.Enabled {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	offset, haveOffset := first(q["offset"])
	limit, haveLimit := first(q["limit"])
	v, err := h.Logger.View(ParseViewQuery(offset, limit, q.Get("level"), q.Get("q"), haveOffset, haveLimit))
	if err != nil {
		h.fail(w, r, fault.Wrap(fault.StorageError, err, ""))
		return
	}
	writeRaw(w, http.StatusOK, v.JSON())
}

func first(values []string) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// timestampParam is _parse_timestamp of a query parameter; empty is none.
func timestampParam(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, true
	}
	t, err := parseTimestamp(s)
	return t, err == nil
}

func (h *HTTP) export(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	if !h.Enabled {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	from, okFrom := timestampParam(q.Get("from"))
	to, okTo := timestampParam(q.Get("to"))
	if !okFrom || !okTo {
		writeError(w, http.StatusBadRequest, "Invalid audit export timestamp")
		return
	}
	if !from.IsZero() && !to.IsZero() && from.After(to) {
		writeError(w, http.StatusBadRequest, "Invalid audit export range")
		return
	}
	if r.Method != http.MethodHead {
		h.Logger.Event(Info, "AUDIT_EXPORT", F("admin", p.Username))
	}
	meta, err := h.Logger.ExportScan()
	if err != nil {
		h.fail(w, r, fault.Wrap(fault.StorageError, err, ""))
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "application/x-ndjson")
	hd.Set("Content-Disposition", `attachment; filename="webssh-audit.jsonl"`)
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-WebSSH-Audit-Scan-Limit", strconv.Itoa(MaxExportScan))
	hd.Set("X-WebSSH-Audit-Scanned", strconv.Itoa(meta.Scanned))
	hd.Set("X-WebSSH-Audit-Truncated", strconv.FormatBool(meta.Truncated))
	hd.Set("X-WebSSH-Audit-Completeness", meta.Completeness())
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, meta.line(MaxExportScan))
	if err := h.Logger.Export(w, ExportFilter{From: from, To: to, Level: Level(q.Get("level")), Query: q.Get("q")}); err != nil {
		// The status is sent; the client sees a short download.
		h.log().ErrorContext(r.Context(), "audit export failed", "error", err)
	}
}

// line is the first line of an export.
func (m ExportMeta) line(limit int) string {
	return `{"type":"webssh_audit_export","scanned":` + strconv.Itoa(m.Scanned) +
		`,"truncated":` + strconv.FormatBool(m.Truncated) + `,"scan_limit":` + strconv.Itoa(limit) + "}\n"
}

// retention needs the step-up audit.retention for "global", spent before
// the body is read and before the switch is checked, as the Python
// decorators ran.
func (h *HTTP) retention(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	if err := h.StepUp.Consume(r.Context(), p, principal.ActionAuditRetention, "global", r.Header.Get(StepUpHeader)); err != nil {
		h.fail(w, r, err)
		return
	}
	if !h.Enabled {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	v, err := decodeLine(body)
	if err != nil || v.kind != kindObject {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	count, ok := v.member("backup_count")
	n, err := strconv.Atoi(count.num)
	if !ok || count.kind != kindInt || err != nil || n < 1 || n > MaxBackupCount {
		writeError(w, http.StatusBadRequest, "backup_count must be an integer between 1 and 90")
		return
	}
	if err := h.Retention.SetAuditBackupCount(r.Context(), n); err != nil {
		h.log().ErrorContext(r.Context(), "audit retention could not be saved", "error", err)
		writeError(w, http.StatusServiceUnavailable, "Audit retention could not be saved")
		return
	}
	if err := h.Logger.SetBackupCount(n); err != nil {
		h.log().WarnContext(r.Context(), "Audit log archive pruning deferred", "error", err)
	}
	h.Logger.Event(Info, "AUDIT_RETENTION_CHANGED", F("admin", p.Username), F("backup_count", n))
	writeRaw(w, http.StatusOK, []byte(`{"backup_count":`+strconv.Itoa(n)+`}`))
}

func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		h.log().ErrorContext(r.Context(), "audit request failed", "path", r.URL.Path, "error", err)
	}
	var b []byte
	b = append(b, `{"success":false,"code":`...)
	b = strconv.AppendQuote(b, string(code))
	b = append(b, `,"error":`...)
	b = appendJSONString(b, message)
	b = append(b, '}')
	writeRaw(w, status, b)
}

func writeError(w http.ResponseWriter, status int, message string) {
	b := appendJSONString([]byte(`{"error":`), message)
	writeRaw(w, status, append(b, '}'))
}

func appendJSONString(b []byte, s string) []byte {
	var sb strings.Builder
	pyString(&sb, s)
	return append(b, sb.String()...)
}

func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body) // #nosec G705 -- JSON with application/json; strings are escaped
}
