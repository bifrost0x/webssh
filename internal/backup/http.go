package backup

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

// Messages of the Python release (admin_backup.py), which the
// administration shows as they are.
const (
	msgBusy          = "another backup or restore operation is active"
	msgNotFound      = "Backup operation not found"
	msgUploadLarge   = "Backup upload is too large"
	msgUploadFailed  = "Backup upload failed"
	msgCreateFailed  = "Backup creation failed"
	msgVerifyFailed  = "Backup verification failed"
	msgInvalid       = "Invalid request"
	msgActive        = "Active operation cannot be cancelled safely"
	msgNeedVerified  = "A verified upload is required"
	msgIncompatible  = "Backup is not compatible with this WebSSH version"
	msgNoLongerValid = "Backup archive is no longer valid"
)

// Limiter answers whether an administrator may start one more action of
// the named kind ("backup_create", "backup_upload", "backup_download",
// "backup_restore"; RATELIMIT_BACKUP_*).
type Limiter func(userID int64, ip, kind string) bool

// Auditor records the security events of the backup routes.
type Auditor interface {
	Security(event string, kv ...any)
}

// HTTP serves the online backup and restore of the administration
// (C-BAK-01 to -04). The edge mounts the routes behind an administrator
// session, CSRF and origin checks; the upload's body is streamed
// (httpapi.Handler.StreamBody).
type HTTP struct {
	Ops    *Operations
	Inst   *Installation
	StepUp StepUp
	// Export writes the online backup of the live database to path.
	Export func(ctx context.Context, path, work string) (Verified, error)
	// Restore runs a confirmed restore in the background (RestoreRunner).
	Restore *RestoreRunner
	Limit   Limiter
	Audit   Auditor
	Logger  *slog.Logger
	// Limits bound uploads (BACKUP_UPLOAD_MAX_SIZE) and every archive.
	Limits Limits
	// Timeout is BACKUP_OPERATION_TIMEOUT, the bound of a status that is
	// shown after it finished.
	Timeout time.Duration
	// Background is the context of the server's background work; the
	// workers end with it.
	Background context.Context
	work       sync.WaitGroup
}

// Register adds the routes relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/api/backups", h.serve(h.create))
	mux.HandleFunc("GET /admin/api/backups/restore/status", h.serve(h.restoreStatus))
	mux.HandleFunc("GET /admin/api/backups/{operation_id}", h.serve(h.status))
	mux.HandleFunc("POST /admin/api/backups/{operation_id}/download", h.download)
	mux.HandleFunc("POST /admin/api/backups/upload", h.serve(h.upload))
	mux.HandleFunc("POST /admin/api/backups/{operation_id}/cancel", h.serve(h.cancel))
	mux.HandleFunc("POST /admin/api/backups/{operation_id}/restore/prepare", h.serve(h.prepare))
	mux.HandleFunc("POST /admin/api/backups/{operation_id}/restore", h.serve(h.restore))
}

// UploadPattern is the route whose body the edge streams.
const UploadPattern = "POST /admin/api/backups/upload"

// Wait waits for the background workers (shutdown).
func (h *HTTP) Wait() { h.work.Wait() }

// writerKey carries the response writer to handlers that extend their
// deadlines.
type writerKey struct{}

type reply struct {
	status int
	body   any
}

type handler func(ctx context.Context, p principal.Principal, r *http.Request) (reply, error)

func (h *HTTP) serve(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := principal.RequireAdmin(r.Context())
		if err == nil {
			var rep reply
			r = r.WithContext(context.WithValue(r.Context(), writerKey{}, w))
			if rep, err = fn(r.Context(), p, r); err == nil {
				writeJSON(w, rep.status, rep.body)
				return
			}
		}
		h.fail(w, r, err)
	}
}

func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		h.logger().ErrorContext(r.Context(), "backup request failed", "path", r.URL.Path, "err", err)
	}
	writeJSON(w, status, map[string]any{"success": false, "code": string(code), "error": message})
}

func (h *HTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h *HTTP) audit(event string, kv ...any) {
	if h.Audit != nil {
		h.Audit.Security(event, kv...)
	}
}

func errorReply(status int, message string) reply {
	return reply{status: status, body: map[string]any{"error": message}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
	_, _ = io.WriteString(w, "\n")
}

func (h *HTTP) consume(ctx context.Context, p principal.Principal, r *http.Request, action principal.Action, target string) error {
	if h.StepUp == nil {
		return fault.New(fault.StepUpRequired, "")
	}
	return h.StepUp.Consume(ctx, p, action, target, r.Header.Get(StepUpHeader))
}

func (h *HTTP) limited(p principal.Principal, r *http.Request, kind string) bool {
	if h.Limit == nil || h.Limit(p.UserID, clientIP(r), kind) {
		return false
	}
	h.audit("RATE_LIMIT_EXCEEDED", "endpoint", kind, "user", p.Username)
	return true
}

func clientIP(r *http.Request) string { return r.RemoteAddr }

// payload is _operation_payload.
func payload(o Operation) map[string]any {
	var summary any
	if o.Summary != nil {
		summary = summaryJSON(*o.Summary)
	}
	var errText any
	if o.Error != "" {
		errText = o.Error
	}
	return map[string]any{"operation_id": o.ID, "kind": o.Kind, "status": string(o.Status), "size": o.Size,
		"summary": summary, "error": errText}
}

// summaryJSON is _archive_summary.
func summaryJSON(s Summary) map[string]any {
	var created any
	if s.CreatedAt != "" {
		created = s.CreatedAt
	}
	return map[string]any{"format_version": s.FormatVersion, "data_schema_version": s.DataSchemaVersion,
		"current_data_schema_version": s.CurrentDataSchemaVersion, "created_at": created, "legacy": s.Legacy,
		"file_count": s.FileCount, "total_uncompressed_size": s.TotalUncompressedSize, "compatible": s.Compatible,
		"compatibility_reason": s.CompatibilityReason, "format": string(s.Kind)}
}

func (h *HTTP) create(ctx context.Context, p principal.Principal, r *http.Request) (reply, error) {
	if err := h.consume(ctx, p, r, principal.ActionBackupCreate, "new"); err != nil {
		return reply{}, err
	}
	if h.limited(p, r, "backup_create") {
		return errorReply(http.StatusTooManyRequests, "Too many backup requests"), nil
	}
	op, err := h.Ops.Create(KindCreated, p.UserID, p.SessionID, StatusPending)
	if errors.Is(err, errBusy) {
		return errorReply(http.StatusConflict, msgBusy), nil
	}
	if err != nil {
		return reply{}, fault.Wrap(fault.Internal, err, "")
	}
	h.audit("BACKUP_CREATION_STARTED", "user", p.Username)
	h.work.Go(func() {
		h.Ops.Update(op.ID, StatusRunning, 0, nil, "")
		v, err := h.Export(h.Background, op.Archive(), op.Dir())
		if err != nil {
			_ = os.Remove(op.Archive())
			h.Ops.Update(op.ID, StatusFailed, 0, nil, msgCreateFailed)
			h.logger().Error("online backup failed", "err", err)
			h.audit("BACKUP_CREATION_FAILED", "user", p.Username)
			return
		}
		info, err := os.Stat(op.Archive())
		if err != nil {
			h.Ops.Update(op.ID, StatusFailed, 0, nil, msgCreateFailed)
			return
		}
		s := goSummary(v)
		h.Ops.Update(op.ID, StatusReady, info.Size(), &s, "")
		h.audit("BACKUP_CREATION_SUCCEEDED", "user", p.Username, "size", info.Size(), "files", s.FileCount)
	})
	return reply{status: http.StatusAccepted, body: payload(op)}, nil
}

// goSummary summarises a verified Go archive this build wrote.
func goSummary(v Verified) Summary {
	s := Summary{Kind: KindGo, FormatVersion: v.Manifest.Version, DataSchemaVersion: v.Manifest.Version,
		CurrentDataSchemaVersion: FormatVersion, CreatedAt: v.Manifest.CreatedAt, FileCount: len(v.Manifest.Files),
		Compatible: true, CompatibilityReason: ReasonCurrent, IncludesSecretKey: v.Manifest.IncludesSecretKey}
	for _, f := range v.Manifest.Files {
		s.TotalUncompressedSize += f.Size
	}
	return s
}

func (h *HTTP) status(_ context.Context, p principal.Principal, r *http.Request) (reply, error) {
	op, err := h.Ops.Get(r.PathValue("operation_id"), p.UserID, p.SessionID)
	if err != nil {
		return errorReply(http.StatusNotFound, msgNotFound), nil
	}
	return reply{status: http.StatusOK, body: payload(op)}, nil
}

func (h *HTTP) cancel(ctx context.Context, p principal.Principal, r *http.Request) (reply, error) {
	id := r.PathValue("operation_id")
	if err := h.consume(ctx, p, r, principal.ActionBackupCancel, id); err != nil {
		return reply{}, err
	}
	op, err := h.Ops.Get(id, p.UserID, p.SessionID)
	if err != nil {
		return errorReply(http.StatusNotFound, msgNotFound), nil
	}
	if op.Status.Active() {
		return errorReply(http.StatusConflict, msgActive), nil
	}
	if err := h.Ops.Remove(id); err != nil {
		return reply{}, fault.Wrap(fault.Internal, err, "")
	}
	return reply{status: http.StatusOK, body: map[string]any{"ok": true}}, nil
}

func (h *HTTP) restoreStatus(_ context.Context, _ principal.Principal, _ *http.Request) (reply, error) {
	state, message := Status(h.Inst.goDir(), h.Timeout, time.Now())
	var msg any
	if message != "" {
		msg = message
	}
	return reply{status: http.StatusOK, body: map[string]any{"state": state, "message": msg}}, nil
}
