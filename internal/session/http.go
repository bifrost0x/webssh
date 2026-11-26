package session

import (
	"context"
	"crypto/hmac"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Auditor writes security events (provided by internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}

// HTTP serves the session list of the signed-in user. The edge mounts it
// behind session, CSRF and origin checks.
type HTTP struct {
	Service *Service
	Audit   Auditor
	Logger  *slog.Logger
}

// Register adds the routes relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/account/sessions", h.list)
	mux.HandleFunc("POST /api/account/sessions/revoke", h.revoke)
}

type sessionJSON struct {
	Handle    string   `json:"handle"`
	Current   bool     `json:"current"`
	Methods   []string `json:"methods"`
	StartedAt string   `json:"started_at"`
	ExpiresAt string   `json:"expires_at"`
}

func (h *HTTP) list(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		writeError(w, r, h.Logger, err)
		return
	}
	sessions, err := h.Service.List(r.Context(), p.UserID)
	if err != nil {
		writeError(w, r, h.Logger, err)
		return
	}
	out := make([]sessionJSON, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionJSON{
			Handle: Handle(h.Service.mac, s.ID), Current: s.ID == p.SessionID, Methods: s.Methods,
			StartedAt: pyISO(s.AuthenticatedAt) + "Z", ExpiresAt: pyISO(s.ExpiresAt) + "Z",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

var handlePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	errSelect  = fault.New(fault.InvalidRequest, "Select a login or all other logins")
	errGone    = fault.New(fault.NotFound, "Login is no longer available")
	errCurrent = fault.New(fault.Conflict, "Use Sign out to end this login")
)

// revoke ends all other sessions ({"others": true}) or one session by its
// handle ({"session": "<hex>"}); the current one ends only by signing out.
func (h *HTTP) revoke(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err == nil {
		var n int
		if n, err = h.revokeSelected(r.Context(), p, r.Body); err == nil {
			if h.Audit != nil {
				h.Audit.Security("BROWSER_LOGINS_REVOKED", "user", p.Username, "count", n)
			}
			writeJSON(w, http.StatusOK, map[string]any{"revoked": n, "cleanup_incomplete": false})
			return
		}
	}
	writeError(w, r, h.Logger, err)
}

func (h *HTTP) revokeSelected(ctx context.Context, p principal.Principal, body io.Reader) (int, error) {
	others, handle, err := parseRevoke(body)
	if err != nil {
		return 0, err
	}
	s := h.Service
	sessions, err := s.List(ctx, p.UserID)
	if err != nil {
		return 0, err
	}
	var ids []string
	for _, sess := range sessions {
		switch {
		case others && sess.ID != p.SessionID:
			ids = append(ids, sess.ID)
		case !others && hmac.Equal([]byte(Handle(s.mac, sess.ID)), []byte(handle)):
			if sess.ID == p.SessionID {
				return 0, errCurrent
			}
			ids = append(ids, sess.ID)
		}
	}
	if !others && len(ids) == 0 {
		return 0, errGone
	}
	var revs []principal.Revocation
	err = s.db.Write(ctx, func(tx *store.Tx) error {
		var err error
		revs, err = s.RevokeSessionsTx(ctx, tx, p.UserID, ids, principal.ReasonRevokedByUser)
		return err
	})
	if err != nil {
		return 0, storageErr(err)
	}
	s.Publish(revs)
	return len(revs), nil
}

func parseRevoke(body io.Reader) (others bool, handle string, err error) {
	raw, err := io.ReadAll(io.LimitReader(body, 4096))
	if err != nil {
		return false, "", errSelect
	}
	var m map[string]jsontext.Value
	if json.Unmarshal(raw, &m) != nil || len(m) != 1 {
		return false, "", errSelect
	}
	if v, ok := m["others"]; ok && string(v) == "true" {
		return true, "", nil
	}
	if v, ok := m["session"]; ok {
		var s string
		if json.Unmarshal(v, &s) == nil && handlePattern.MatchString(s) {
			return false, s, nil
		}
	}
	return false, "", errSelect
}

type errorBody struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Error   string `json:"error"`
}

func writeError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		if logger == nil {
			logger = slog.Default()
		}
		logger.ErrorContext(r.Context(), "session request failed", "path", r.URL.Path, "error", err)
	}
	writeJSON(w, status, errorBody{Code: string(code), Error: message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}
