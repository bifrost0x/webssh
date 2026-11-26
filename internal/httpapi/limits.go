package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// controlRequestLimit bounds the body of every unsafe request without a
// limit of its own (CONTROL_REQUEST_LIMIT of request_limits.py).
const controlRequestLimit = 64 << 10

// bodyLimit returns the body limit of an unsafe request, as
// request_limits.py chooses it for the routes of this preview: the
// recovery and TOTP routes MAX_RECOVERY_JSON_SIZE, the passkey routes
// MAX_WEBAUTHN_JSON_SIZE, everything else 64 KiB. The whole body is read
// before the CSRF check, so no handler sees a partial body.
func (h *Handler) bodyLimit(path string) int64 {
	s := h.cfg.Stores
	switch {
	case strings.HasPrefix(path, "/api/totp/"), path == "/api/recovery-codes",
		path == "/api/auth/recovery", path == "/api/auth/mfa/disable",
		path == "/login/recovery", strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/recovery"):
		if s.MaxRecoveryJSONSize > 0 {
			return int64(s.MaxRecoveryJSONSize)
		}
	case strings.HasPrefix(path, "/api/webauthn/"):
		if s.MaxWebAuthnJSONSize > 0 {
			return int64(s.MaxWebAuthnJSONSize)
		}
	}
	return controlRequestLimit
}

// tooLarge answers 413: JSON with the Python text for API clients, plain
// otherwise.
func (h *Handler) tooLarge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	h.fail(w, r, fault.New(fault.TooLarge, "Request body too large"), "", "")
}

var errPreview = fault.New(fault.NotAvailableInPreview, "")

// notAvailable answers a route this preview does not build. It reads
// nothing of the request.
func (h *Handler) notAvailable(w http.ResponseWriter, r *http.Request) {
	h.fail(w, r, errPreview, "", "")
}

// goneBody tells a cached Socket.IO page that the transport changed
// (ADR 0005).
type goneBody struct {
	Success  bool       `json:"success"`
	Code     fault.Code `json:"code"`
	Error    string     `json:"error"`
	Realtime string     `json:"realtime"`
}

// gone answers /socket.io with 410: the realtime transport is the native
// WebSocket endpoint now; a page loaded from the Python release must
// reload.
func gone(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusGone, goneBody{
		Code:     fault.VersionUnsupported,
		Error:    "Socket.IO is no longer served. Reload the page to use the current realtime connection.",
		Realtime: protocol.Subprotocol(protocol.Version),
	})
}

// readBody buffers the body of an unsafe request up to limit bytes and
// replaces it with the buffer, so the CSRF check and the handler both see
// it. It reports false when the body is larger.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool, error) {
	if r.ContentLength > limit {
		return nil, false, nil
	}
	var buf bytes.Buffer
	_, err := buf.ReadFrom(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, false, nil
		}
		return nil, true, err
	}
	r.Body = readCloser{bytes.NewReader(buf.Bytes())}
	return buf.Bytes(), true, nil
}

type readCloser struct{ *bytes.Reader }

func (readCloser) Close() error { return nil }
