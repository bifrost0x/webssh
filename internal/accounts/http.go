package accounts

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

const maxBody = 16 << 10

// HTTP serves the account list, account creation and (RegisterAdmin)
// the account administration of the admin panel.
// The edge mounts it behind session, CSRF and origin checks.
type HTTP struct {
	Accounts *Service
	StepUp   StepUp
	// Gates gates the recovery reset; nil answers it with 404.
	Gates Gates
	// Enabled is ADMIN_PANEL_ENABLED; off answers 404.
	Enabled bool
	Logger  *slog.Logger
}

// Register adds the routes relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/users", h.serve(h.list))
	mux.HandleFunc("POST /admin/api/users", h.serve(h.create))
}

type handler func(ctx context.Context, p principal.Principal, r *http.Request) (int, any, error)

func (h *HTTP) serve(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.Enabled {
			http.NotFound(w, r)
			return
		}
		p, err := principal.RequireAdmin(r.Context())
		if err == nil {
			var status int
			var body any
			if status, body, err = fn(r.Context(), p, r); err == nil {
				writeJSON(w, status, body)
				return
			}
		}
		status, code, message := fault.Status(err)
		if code == fault.Internal || code == fault.StorageError {
			logger := h.Logger
			if logger == nil {
				logger = slog.Default()
			}
			logger.ErrorContext(r.Context(), "account request failed", "path", r.URL.Path, "error", err)
		}
		writeJSON(w, status, map[string]any{"success": false, "code": string(code), "error": message})
	}
}

// userJSON is _user_to_dict of the Python release.
type userJSON struct {
	ID                   int64   `json:"id"`
	Username             string  `json:"username"`
	IsAdmin              bool    `json:"is_admin"`
	IsLocked             bool    `json:"is_locked"`
	MFAEnabled           bool    `json:"mfa_enabled"`
	LDAPManaged          bool    `json:"ldap_managed"`
	GitHubManaged        bool    `json:"github_managed"`
	AdminManagedByConfig bool    `json:"admin_managed_by_config"`
	CreatedAt            *string `json:"created_at"`
	LastLogin            *string `json:"last_login"`
}

func (s *Service) userJSON(a Account) userJSON {
	u := userJSON{ID: a.ID, Username: a.Username, IsAdmin: a.IsAdmin, IsLocked: a.IsLocked, MFAEnabled: a.MFARequired,
		LDAPManaged: a.Managed == ManagedLDAP, GitHubManaged: a.Managed == ManagedGitHub, AdminManagedByConfig: s.Admins.Manages(a)}
	if !a.CreatedAt.IsZero() {
		v := pyISO(a.CreatedAt)
		u.CreatedAt = &v
	}
	if !a.LastLogin.IsZero() {
		v := pyISO(a.LastLogin)
		u.LastLogin = &v
	}
	return u
}

func (h *HTTP) list(ctx context.Context, _ principal.Principal, _ *http.Request) (int, any, error) {
	accounts, err := h.Accounts.List(ctx)
	if err != nil {
		return 0, nil, err
	}
	out := make([]userJSON, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, h.Accounts.userJSON(a))
	}
	return http.StatusOK, map[string]any{"users": out}, nil
}

var errPayload = fault.New(fault.InvalidRequest, "Invalid user payload")

type createJSON struct {
	Username jsontext.Value `json:"username"`
	Password jsontext.Value `json:"password"`
	IsAdmin  jsontext.Value `json:"is_admin"`
}

// create needs a step-up grant for user.create bound to the stripped
// name ("invalid-payload" for a body without one, as in the Python
// release); the grant is checked before the body.
func (h *HTTP) create(ctx context.Context, p principal.Principal, r *http.Request) (int, any, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		raw = nil
	}
	var in createJSON
	valid := raw != nil && json.Unmarshal(raw, &in, json.RejectUnknownMembers(false)) == nil
	username, ok := jsonString(in.Username)
	target := "invalid-payload"
	if valid && ok {
		target = strings.TrimSpace(username)
	} else {
		valid = false
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionUserCreate, target, r.Header.Get(StepUpHeader)); err != nil {
		return 0, nil, err
	}
	password, okPassword := jsonString(in.Password)
	makeAdmin, okAdmin := false, true
	if len(in.IsAdmin) > 0 {
		makeAdmin, okAdmin = jsonBool(in.IsAdmin)
	}
	if !valid || !okPassword || !okAdmin {
		return 0, nil, errPayload
	}
	acc, err := h.Accounts.Create(ctx, CreateRequest{Username: target, Password: password, ByAdmin: true, Admin: makeAdmin})
	if err != nil {
		return 0, nil, err
	}
	h.Accounts.logger().Info("Admin created user", "admin", p.Username, "user", acc.Username, "is_admin", makeAdmin)
	if h.Accounts.Audit != nil {
		h.Accounts.Audit.Security("ADMIN_USER_CREATED", "admin", p.Username, "user", acc.Username, "is_admin", makeAdmin)
	}
	return http.StatusCreated, map[string]any{"user": h.Accounts.userJSON(acc)}, nil
}

// jsonString accepts only a JSON string (isinstance(value, str)).
func jsonString(v jsontext.Value) (string, bool) {
	var s string
	if v.Kind() != '"' || json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

// jsonBool accepts only true or false (type(value) is bool).
func jsonBool(v jsontext.Value) (bool, bool) {
	switch v.Kind() {
	case 't':
		return true, true
	case 'f':
		return false, true
	}
	return false, false
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}
