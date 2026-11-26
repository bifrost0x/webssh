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
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Cookies writes and reads the browser cookies of a session. Go uses its
// own tokens (decision D-02); the cookie keeps the configured
// SESSION_COOKIE_NAME, so a reverse proxy rule on the name still applies.
type Cookies struct {
	// Name is SESSION_COOKIE_NAME.
	Name string
	// Path is APPLICATION_ROOT or "/".
	Path string
	// Secure is SESSION_COOKIE_SECURE.
	Secure bool
}

// BindingSuffix names the pre-sign-in cookie: Name + BindingSuffix.
const BindingSuffix = "_binding"

func (c Cookies) path() string {
	if c.Path == "" {
		return "/"
	}
	return c.Path
}

func (c Cookies) cookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: c.path(), HttpOnly: true, Secure: c.Secure, SameSite: http.SameSiteLaxMode}
}

// Token returns the session token of a request, or "".
func (c Cookies) Token(r *http.Request) string {
	if ck, err := r.Cookie(c.Name); err == nil && len(ck.Value) <= maxTokenLen {
		return ck.Value
	}
	return ""
}

// Set writes the session cookie. A remembered session gets an expiry; any
// other cookie ends with the browser session.
func (c Cookies) Set(w http.ResponseWriter, token string, s Session) {
	ck := c.cookie(c.Name, token)
	if s.Remember {
		ck.Expires = s.ExpiresAt
		ck.MaxAge = max(1, int(time.Until(s.ExpiresAt).Seconds()))
	}
	http.SetCookie(w, ck)
}

// Clear removes the session cookie.
func (c Cookies) Clear(w http.ResponseWriter) {
	ck := c.cookie(c.Name, "")
	ck.MaxAge = -1
	http.SetCookie(w, ck)
}

// Binding returns the browser binding of a visitor that is not signed in
// yet, creating it if needed. It ties a pending second-factor step to the
// browser that entered the password (browser_session_binding) and is the
// anchor for pre-sign-in CSRF tokens.
func (c Cookies) Binding(w http.ResponseWriter, r *http.Request) string {
	if ck, err := r.Cookie(c.Name + BindingSuffix); err == nil && validBinding(ck.Value) {
		return ck.Value
	}
	v := randomText(32)
	http.SetCookie(w, c.cookie(c.Name+BindingSuffix, v))
	return v
}

// CurrentBinding returns the binding of a request without creating one.
func (c Cookies) CurrentBinding(r *http.Request) string {
	if ck, err := r.Cookie(c.Name + BindingSuffix); err == nil && validBinding(ck.Value) {
		return ck.Value
	}
	return ""
}

// RotateBinding replaces the binding, so a sign-in never continues with a
// value an attacker planted before it.
func (c Cookies) RotateBinding(w http.ResponseWriter) string {
	v := randomText(32)
	http.SetCookie(w, c.cookie(c.Name+BindingSuffix, v))
	return v
}

var bindingPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func validBinding(v string) bool { return bindingPattern.MatchString(v) }

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
