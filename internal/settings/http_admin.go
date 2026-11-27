package settings

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

// StepUp consumes a step-up grant (provided by internal/auth/stepup).
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// Auditor writes security events (provided by internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
	SecurityWarning(event string, kv ...any)
}

// AdminHTTP serves GET and POST /admin/api/settings, the administrator's
// application settings and integration switches (C-ASET-01, -04, -05).
// The edge mounts it behind session, CSRF, origin and admin checks; the
// handlers check the administrator again.
type AdminHTTP struct {
	Settings *Service
	StepUp   StepUp
	Audit    Auditor
	// Enabled is ADMIN_PANEL_ENABLED; off answers 404.
	Enabled bool
	// TailscaleSSHEnabled is TAILSCALE_SSH_ENABLED, shown beside the
	// tailnet restriction.
	TailscaleSSHEnabled bool
	// Changed runs after a successful write with the changed settings, for
	// the effects outside the store (gateway, reachability cache).
	Changed func(ctx context.Context, changes map[string]AdminChange)
	Logger  *slog.Logger
}

// Register adds the routes relative to APPLICATION_ROOT.
func (h *AdminHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/settings", h.get)
	mux.HandleFunc("POST /admin/api/settings", h.post)
}

func (h *AdminHTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h *AdminHTTP) admin(w http.ResponseWriter, r *http.Request) (principal.Principal, bool) {
	if !h.Enabled {
		http.NotFound(w, r)
		return principal.Principal{}, false
	}
	p, err := principal.RequireAdmin(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return p, false
	}
	return p, true
}

func (h *AdminHTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		h.logger().ErrorContext(r.Context(), "admin settings request failed", "error", err)
	}
	writeJSON(w, status, errorBody{Success: false, Code: string(code), Error: message})
}

func (h *AdminHTTP) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	h.answer(w, r)
}

func (h *AdminHTTP) answer(w http.ResponseWriter, r *http.Request) {
	app, err := h.Settings.App(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(app))
}

// view is the body of admin_get_settings, plus the role permissions.
func (h *AdminHTTP) view(a App) map[string]any {
	runtime := map[string]any{}
	body := map[string]any{"setting_sources": a.settingSources(), "runtime_features": runtime}
	for _, name := range runtimeFeatureOrder {
		st := a.RuntimeFeature(name)
		var saved any
		if st.Saved != nil {
			saved = *st.Saved
		}
		runtime[name] = map[string]any{"enabled": st.Enabled, "source": st.Source, "locked": st.Locked,
			"environment_key": st.EnvironmentKey, "saved_value": saved, "migrated": st.Migrated}
		body[name] = st.Enabled
	}
	body["registration_enabled"] = a.RegistrationEnabled
	body["login_username_limit"] = a.SignIn.UsernameLimit
	body["login_username_global_limit"] = a.SignIn.UsernameGlobalLimit
	body["ratelimit_ipv6_prefix"] = a.SignIn.IPv6Prefix
	body["tailscale_ssh_restrict_tailnet_routes"] = a.TailnetRouteRestricted
	body["tailscale_ssh_enabled"] = h.TailscaleSSHEnabled
	body["ssh_gateway_enabled"] = a.SSHGatewayEnabled
	body["herdr_enabled"] = a.HerdrEnabled
	body["support_links_enabled"] = a.SupportLinksEnabled
	body["credentials_enabled"] = a.CredentialsEnabled
	body["automation_enabled"] = a.AutomationEnabled
	body[SettingDiscoveryUsers] = slices.Contains(a.Policy.Discovery, RoleUser)
	body[SettingReachabilityUsers] = slices.Contains(a.Policy.Reachability, RoleUser)
	return body
}

// settingSources is native_setting_sources: the lock state of the admin
// switches with an environment counterpart.
func (a App) settingSources() map[string]any {
	automation := a.env.Explicit["AUTOMATION_ENABLED"]
	source := "admin"
	if automation {
		source = "compose"
	}
	registration := "admin"
	if a.env.Production {
		registration = "production"
	}
	return map[string]any{
		"automation_enabled":   map[string]any{"locked": automation, "environment_key": "AUTOMATION_ENABLED", "source": source},
		"registration_enabled": map[string]any{"locked": a.env.Production, "environment_key": "REGISTRATION_ENABLED", "source": registration},
	}
}

type badRequest map[string]any

func (h *AdminHTTP) post(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	if err := h.StepUp.Consume(r.Context(), p, principal.ActionSettingsUpdate, "global", r.Header.Get(StepUpHeader)); err != nil {
		h.fail(w, r, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	var data map[string]jsontext.Value
	if err != nil || len(raw) > maxBody || json.Unmarshal(raw, &data) != nil || data == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid settings payload"})
		return
	}
	app, err := h.Settings.App(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	changes, status, refusal := h.check(app, data)
	if refusal != nil {
		writeJSON(w, status, refusal)
		return
	}
	results, err := h.Settings.UpdateAdmin(r.Context(), changes)
	if gb, ok := errors.AsType[ErrGlobalBelowSource](err); ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": globalBelowSourceMessage, "code": "global_limit_below_source_limit", "setting": gb.Setting})
		return
	}
	if err != nil {
		h.logger().ErrorContext(r.Context(), "Admin settings could not be saved", "error", err, "admin", p.Username)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Settings could not be saved"})
		return
	}
	h.audit(p, app, results)
	if h.Changed != nil {
		h.Changed(r.Context(), results)
	}
	h.answer(w, r)
}

// check validates the request in the order of admin_set_settings and
// returns the accepted changes or the refusal with its status. Members
// that name no setting are ignored, as the Python release ignores them.
func (h *AdminHTTP) check(a App, data map[string]jsontext.Value) (map[string]any, int, badRequest) {
	sources := a.settingSources()
	for _, name := range []string{"automation_enabled", "registration_enabled"} {
		policy := sources[name].(map[string]any)
		if _, ok := data[name]; ok && policy["locked"] == true && policy["source"] != "production" {
			return nil, http.StatusConflict, badRequest{"error": "Setting is controlled by deployment configuration",
				"code": "deployment_locked", "setting": name, "policy": policy}
		}
	}
	changes := map[string]any{}
	for _, name := range runtimeFeatureOrder {
		v, ok := data[name]
		if !ok {
			continue
		}
		b, isBool := asBool(v)
		if !isBool {
			return nil, http.StatusBadRequest, badRequest{"error": "Expected a boolean", "setting": name}
		}
		if st := a.RuntimeFeature(name); st.Locked {
			return nil, http.StatusConflict, badRequest{"error": "Setting is controlled by Compose/environment",
				"code": "deployment_locked", "setting": name, "policy": h.view(a)["runtime_features"].(map[string]any)[name]}
		}
		changes[name] = b
	}
	for _, name := range []string{"credentials_enabled", "automation_enabled", "ssh_gateway_enabled", "herdr_enabled",
		"support_links_enabled", "tailscale_ssh_restrict_tailnet_routes", SettingDiscoveryUsers, SettingReachabilityUsers} {
		if v, ok := data[name]; ok {
			b, isBool := asBool(v)
			if !isBool {
				return nil, http.StatusBadRequest, badRequest{"error": name + " must be a boolean"}
			}
			changes[name] = b
		}
	}
	for _, bound := range SignInBounds {
		v, ok := data[bound.Name]
		if !ok {
			continue
		}
		n, isInt := asInt(v)
		if !isInt || v.Kind() != '0' || n < int64(bound.Min) || n > int64(bound.Max) {
			return nil, http.StatusBadRequest, badRequest{"error": bound.Name + " must be a whole number from " +
				itoa(bound.Min) + " to " + itoa(bound.Max), "code": "out_of_range", "setting": bound.Name,
				"min": bound.Min, "max": bound.Max}
		}
		changes[bound.Name] = n
	}
	if v, ok := data["registration_enabled"]; ok {
		b, isBool := asBool(v)
		if !isBool {
			return nil, http.StatusBadRequest, badRequest{"error": "registration_enabled must be a boolean"}
		}
		if a.env.Production && b {
			return nil, http.StatusBadRequest, badRequest{"error": "Registration cannot be enabled in the production profile"}
		}
		changes["registration_enabled"] = b
	}
	return changes, 0, nil
}
