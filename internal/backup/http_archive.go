package backup

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// download streams a ready backup once: the copy on the server is
// removed when the stream ends, completed or not.
func (h *HTTP) download(w http.ResponseWriter, r *http.Request) {
	p, err := principal.RequireAdmin(r.Context())
	id := r.PathValue("operation_id")
	if err == nil {
		err = h.consume(r.Context(), p, r, principal.ActionBackupDownload, id)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.limited(p, r, "backup_download") {
		rep := errorReply(http.StatusTooManyRequests, "Too many backup download requests")
		writeJSON(w, rep.status, rep.body)
		return
	}
	op, err := h.Ops.ClaimDownload(id, p.UserID, p.SessionID)
	if err != nil {
		rep := errorReply(http.StatusNotFound, msgNotFound)
		writeJSON(w, rep.status, rep.body)
		return
	}
	defer func() { _ = h.Ops.Remove(op.ID) }()
	f, err := os.Open(op.Archive())
	if err != nil {
		h.fail(w, r, fault.Wrap(fault.Internal, err, ""))
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		h.fail(w, r, fault.Wrap(fault.Internal, err, ""))
		return
	}
	// The archive may be large; the edge's write deadline is for
	// ordinary requests.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(h.timeout()))
	name := "webssh-backup-" + time.Now().UTC().Format("20060102T150405Z") + ".tar"
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", formatInt(info.Size()))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	h.audit("BACKUP_DOWNLOADED", "user", p.Username, "size", info.Size())
	if _, err := io.Copy(w, f); err != nil {
		h.logger().Warn("backup download ended early", "err", err)
	}
}

func (h *HTTP) timeout() time.Duration {
	if h.Timeout > 0 {
		return h.Timeout
	}
	return DefaultLimits.OperationTimeout
}

func formatInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// upload stores an archive (at most BACKUP_UPLOAD_MAX_SIZE bytes, read
// after the session, CSRF header and step-up checks) and verifies it in
// the background.
func (h *HTTP) upload(ctx context.Context, p principal.Principal, r *http.Request) (reply, error) {
	if err := h.consume(ctx, p, r, principal.ActionBackupUpload, "upload"); err != nil {
		return reply{}, err
	}
	if h.limited(p, r, "backup_upload") {
		return errorReply(http.StatusTooManyRequests, "Too many backup upload requests"), nil
	}
	op, err := h.Ops.Create(KindUploaded, p.UserID, p.SessionID, StatusUploading)
	if errors.Is(err, errBusy) {
		return errorReply(http.StatusConflict, msgBusy), nil
	}
	if err != nil {
		return reply{}, fault.Wrap(fault.Internal, err, "")
	}
	size, err := h.receive(r, op.Archive())
	if err != nil {
		_ = h.Ops.Remove(op.ID)
		if errors.Is(err, errTooLarge) {
			return errorReply(http.StatusRequestEntityTooLarge, msgUploadLarge), nil
		}
		return errorReply(http.StatusBadRequest, msgUploadFailed), nil
	}
	h.audit("BACKUP_UPLOADED", "user", p.Username, "size", size)
	h.Ops.Update(op.ID, StatusVerifying, size, nil, "")
	h.work.Go(func() {
		s, err := Inspect(h.Background, h.Inst, op.Archive())
		if err != nil {
			_ = os.Remove(op.Archive())
			h.Ops.Update(op.ID, StatusFailed, 0, nil, msgVerifyFailed)
			h.audit("BACKUP_VERIFICATION_FAILED", "user", p.Username)
			return
		}
		h.Ops.Update(op.ID, StatusVerified, size, &s, "")
		h.audit("BACKUP_VERIFICATION_SUCCEEDED", "user", p.Username, "size", size, "files", s.FileCount)
	})
	op.Status, op.Size = StatusVerifying, size
	return reply{status: http.StatusAccepted, body: payload(op)}, nil
}

var errTooLarge = errors.New("backup: upload too large")

func (h *HTTP) uploadLimit() int64 {
	if h.Limits.UploadMaxSize > 0 {
		return h.Limits.UploadMaxSize
	}
	return DefaultLimits.UploadMaxSize
}

// receive writes the request body to path (a new file, mode 0600) and
// syncs it.
func (h *HTTP) receive(r *http.Request, path string) (int64, error) {
	limit := h.uploadLimit()
	if r.ContentLength > limit {
		return 0, errTooLarge
	}
	// The upload may take longer than the edge's read deadline of
	// ordinary requests.
	if w, ok := r.Context().Value(writerKey{}).(http.ResponseWriter); ok {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(h.timeout()))
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the operation's private directory
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, io.LimitReader(r.Body, limit+1))
	if err == nil && n > limit {
		err = errTooLarge
	}
	if err == nil && n < 4 {
		err = errors.New("backup: upload is malformed")
	}
	if err = errors.Join(err, out.Sync(), out.Close()); err != nil {
		return 0, err
	}
	return n, nil
}

// readObject reads a bounded JSON object body; ok is false for anything
// else (request.get_json(silent=True) is not a dict).
func readObject(r *http.Request) (map[string]jsontext.Value, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<10+1))
	if err != nil || len(raw) > 16<<10 || jsontext.Value(raw).Kind() != '{' {
		return nil, false
	}
	var out map[string]jsontext.Value
	if json.Unmarshal(raw, &out) != nil {
		return nil, false
	}
	return out, true
}

func isTrue(v jsontext.Value) bool { return string(v) == "true" }

func jsonString(v jsontext.Value) (string, bool) {
	var s string
	if v.Kind() != '"' || json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

func (h *HTTP) prepare(ctx context.Context, p principal.Principal, r *http.Request) (reply, error) {
	id := r.PathValue("operation_id")
	if err := h.consume(ctx, p, r, principal.ActionBackupRestorePrepare, id); err != nil {
		return reply{}, err
	}
	body, ok := readObject(r)
	if !ok {
		return errorReply(http.StatusBadRequest, msgInvalid), nil
	}
	if !isTrue(body["acknowledge_sensitive_restore"]) {
		return errorReply(http.StatusBadRequest, "Restore acknowledgement is required"), nil
	}
	op, err := h.Ops.Get(id, p.UserID, p.SessionID)
	if err != nil {
		return errorReply(http.StatusNotFound, msgNotFound), nil
	}
	if op.Kind != KindUploaded || op.Status != StatusVerified {
		return errorReply(http.StatusConflict, msgNeedVerified), nil
	}
	if rep, bad := h.incompatible(ctx, op); bad {
		return rep, nil
	}
	token, err := h.Ops.PrepareRestore(id, p.UserID, p.SessionID)
	if err != nil {
		return errorReply(http.StatusConflict, msgNeedVerified), nil
	}
	return reply{status: http.StatusOK, body: map[string]any{"confirmation_token": token, "confirmation_phrase": "RESTORE",
		"warning": "Restore replaces the current persistent state."}}, nil
}

// incompatible re-verifies the uploaded archive, as the Python release
// does before every restore step.
func (h *HTTP) incompatible(ctx context.Context, op Operation) (reply, bool) {
	s, err := Inspect(ctx, h.Inst, op.Archive())
	if err != nil {
		return errorReply(http.StatusConflict, msgNoLongerValid), true
	}
	if !s.Compatible {
		return reply{status: http.StatusConflict, body: map[string]any{"error": msgIncompatible, "reason": s.CompatibilityReason}}, true
	}
	return reply{}, false
}

func (h *HTTP) restore(ctx context.Context, p principal.Principal, r *http.Request) (reply, error) {
	id := r.PathValue("operation_id")
	if err := h.consume(ctx, p, r, principal.ActionBackupRestore, id); err != nil {
		return reply{}, err
	}
	if h.limited(p, r, "backup_restore") {
		return errorReply(http.StatusTooManyRequests, "Too many restore attempts"), nil
	}
	body, ok := readObject(r)
	if !ok {
		return errorReply(http.StatusBadRequest, msgInvalid), nil
	}
	phrase, _ := jsonString(body["confirmation_phrase"])
	if !isTrue(body["confirm_destructive_restore"]) || phrase != "RESTORE" {
		return errorReply(http.StatusBadRequest, "Explicit restore confirmation is required"), nil
	}
	op, err := h.Ops.Get(id, p.UserID, p.SessionID)
	if err != nil {
		return errorReply(http.StatusNotFound, msgNotFound), nil
	}
	if rep, bad := h.incompatible(ctx, op); bad {
		return rep, nil
	}
	token, _ := jsonString(body["confirmation_token"])
	if op, err = h.Ops.BeginRestore(id, p.UserID, p.SessionID, token); err != nil {
		return errorReply(http.StatusConflict, "Restore confirmation expired or invalid"), nil
	}
	if h.Restore == nil {
		h.Ops.ResetUnstartedRestore(op.ID)
		return reply{status: http.StatusServiceUnavailable, body: map[string]any{"error": "Restore could not be started",
			"code": "RESTORE_START_FAILED"}}, nil
	}
	if err := h.Restore.Start(h.Background, op, p.Username, &h.work); err != nil {
		h.Ops.ResetUnstartedRestore(op.ID)
		h.audit("RESTORE_START_FAILED", "user", p.Username)
		h.logger().Error("restore not started", "err", err)
		return reply{status: http.StatusServiceUnavailable, body: map[string]any{"error": "Restore could not be started",
			"code": "RESTORE_START_FAILED"}}, nil
	}
	h.audit("RESTORE_STARTED", "user", p.Username)
	return reply{status: http.StatusAccepted, body: payload(op)}, nil
}
