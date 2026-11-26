package ldap

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// maxJSONBytes bounds the bodies of the administration routes
// (_MAX_LDAP_JSON_BYTES).
const maxJSONBytes = 4096

// HTTP serves the LDAP administration routes. The edge mounts them behind
// session, CSRF and origin checks.
type HTTP struct {
	Service *Service
	// AdminPanel is ADMIN_PANEL_ENABLED; off answers 404.
	AdminPanel bool
	// Limiter and StatusRule rate-limit the status probe per
	// administrator and source (LDAP_LOGIN_RATE_LIMIT), when Limits is
	// enabled (RATELIMIT_ENABLED).
	Limits     auth.FactorLimits
	StatusRule auth.Rule
}

// Register adds the routes relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/ldap/status", h.admin(h.status))
	mux.HandleFunc("POST /admin/api/users/{user_id}/ldap-link", h.admin(h.link))
	mux.HandleFunc("GET /admin/api/users/{user_id}/ldap-identity", h.admin(h.identity))
	mux.HandleFunc("DELETE /admin/api/users/{user_id}/ldap-identities/{identity_id}", h.admin(h.unlink))
}

type handler func(w http.ResponseWriter, r *http.Request, p principal.Principal) (int, any, error)

// admin answers 404 without the admin panel or with LDAP inactive, as the
// Python release did (admin_required, the security feature gate).
func (h *HTTP) admin(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.AdminPanel || !h.Service.active(r.Context()) {
			http.NotFound(w, r)
			return
		}
		p, err := principal.RequireAdmin(r.Context())
		if err == nil {
			var status int
			var body any
			if status, body, err = fn(w, r, p); err == nil {
				auth.WriteJSON(w, status, body)
				return
			}
		}
		auth.WriteError(w, r, h.Service.Logger, err)
	}
}

func pathID(r *http.Request, name string) (int64, bool) {
	v, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return v, err == nil && v >= 0 && strconv.FormatInt(v, 10) == r.PathValue(name)
}

var (
	errInvalidRequest = fault.New(fault.InvalidRequest, "Invalid request")
	errTooLarge       = fault.New(fault.TooLarge, "Request body too large")
	errStatusLimited  = func() error {
		e := fault.New(fault.RateLimited, "Too many LDAP diagnostic requests")
		e.RetryAfter = time.Minute
		return e
	}()
)

// readObject reads a JSON object of at most 4096 bytes (_bounded_json).
func readObject(r *http.Request) (map[string]jsontext.Value, error) {
	if r.ContentLength > maxJSONBytes {
		return nil, errTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBytes+1))
	if err != nil {
		return nil, errInvalidRequest
	}
	if len(raw) > maxJSONBytes {
		return nil, errTooLarge
	}
	var obj map[string]jsontext.Value
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return nil, errInvalidRequest
	}
	return obj, nil
}

func jsonString(obj map[string]jsontext.Value, key string) (string, bool) {
	raw, ok := obj[key]
	if !ok || raw.Kind() != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// statusJSON is the answer of the status probe.
type statusJSON struct {
	Enabled   bool   `json:"enabled"`
	Provider  string `json:"provider"`
	Ready     bool   `json:"ready"`
	Transport string `json:"transport"`
}

func (h *HTTP) status(_ http.ResponseWriter, r *http.Request, p principal.Principal) (int, any, error) {
	if h.Limits.UserLimited(r, p.UserID, "ldap_status", h.StatusRule) {
		return 0, nil, errStatusLimited
	}
	ready, transport := h.Service.Status(r.Context(), p)
	body := statusJSON{Enabled: true, Provider: h.Service.Provider, Ready: ready, Transport: transport}
	if !ready {
		return http.StatusServiceUnavailable, body, nil
	}
	return http.StatusOK, body, nil
}

// grantOf is the step-up grant of the request.
func grantOf(r *http.Request) string { return r.Header.Get(auth.StepUpHeader) }

func (h *HTTP) link(_ http.ResponseWriter, r *http.Request, p principal.Principal) (int, any, error) {
	userID, ok := pathID(r, "user_id")
	if !ok {
		return 0, nil, fault.New(fault.NotFound, "")
	}
	obj, berr := readObject(r)
	req := LinkRequest{Malformed: berr}
	req.ConfirmUsername, _ = jsonString(obj, "confirm_username")
	req.DirectoryUsername, req.Valid = jsonString(obj, "directory_username")
	id, err := h.Service.AdminLink(r.Context(), p, userID, req, grantOf(r))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, map[string]any{"id": id}, nil
}

type identityJSON struct {
	ID                int64   `json:"id"`
	Provider          string  `json:"provider"`
	DirectoryUsername string  `json:"directory_username"`
	CreatedAt         string  `json:"created_at"`
	LastVerifiedAt    *string `json:"last_verified_at"`
}

func (h *HTTP) identity(_ http.ResponseWriter, r *http.Request, _ principal.Principal) (int, any, error) {
	userID, ok := pathID(r, "user_id")
	if !ok {
		return 0, nil, fault.New(fault.NotFound, "")
	}
	if _, err := h.Service.account(r.Context(), userID); err != nil {
		return 0, nil, err
	}
	id, found, err := h.Service.IdentityOf(r.Context(), userID)
	if err != nil {
		return 0, nil, err
	}
	if !found {
		return http.StatusOK, map[string]any{"identity": nil}, nil
	}
	out := identityJSON{ID: id.ID, Provider: id.Provider, DirectoryUsername: id.DirectoryUsername, CreatedAt: pyISO(id.CreatedAt)}
	if !id.LastVerifiedAt.IsZero() {
		v := pyISO(id.LastVerifiedAt)
		out.LastVerifiedAt = &v
	}
	return http.StatusOK, map[string]any{"identity": out}, nil
}

func (h *HTTP) unlink(_ http.ResponseWriter, r *http.Request, p principal.Principal) (int, any, error) {
	userID, ok1 := pathID(r, "user_id")
	identityID, ok2 := pathID(r, "identity_id")
	if !ok1 || !ok2 {
		return 0, nil, fault.New(fault.NotFound, "")
	}
	obj, berr := readObject(r)
	req := UnlinkRequest{Malformed: berr}
	req.ConfirmUsername, _ = jsonString(obj, "confirm_username")
	req.NewPassword, req.HasPassword = jsonString(obj, "new_password")
	if err := h.Service.AdminUnlink(r.Context(), p, userID, identityID, req, grantOf(r)); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"ok": true}, nil
}

// pyISO renders t like Python's naive datetime.isoformat() in UTC, as the
// stored times of the Python release were naive UTC.
func pyISO(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}
