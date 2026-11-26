package httpapi

import (
	"regexp"
	"strings"
)

// Access says who may reach a route and which checks of the edge run in
// front of it.
type Access uint8

// Access levels. The zero value is not a level: a route the catalog does
// not know is refused.
const (
	// AccessPublic routes need no session: the sign-in steps before a session
	// exists. A valid session is still put into the context, and unsafe
	// methods still need the CSRF token and a same-origin request.
	AccessPublic Access = iota + 1
	// AccessUser routes need a session that is not a recovery session.
	AccessUser
	// AccessRepair routes need a session and also admit a recovery session:
	// factor repair, the settings page and sign-out (C-MFA-09).
	AccessRepair
	// AccessAdmin routes need an administrator session that is not a recovery
	// session and answer 404 while ADMIN_PANEL_ENABLED is false.
	AccessAdmin
	// AccessUpgrade is the realtime endpoint. It checks origin and session
	// itself before the upgrade; the edge adds only the headers and the
	// client address, and no deadline ends the connection.
	AccessUpgrade
	// AccessProbe routes (/health, /ready) and static files never look at the
	// session or the CSRF binding.
	AccessProbe
	// AccessPreview routes are planned but not built in this preview. They
	// answer 501 before anything reads the request.
	AccessPreview
)

// String returns the level for logs and tests.
func (a Access) String() string {
	switch a {
	case AccessPublic:
		return "public"
	case AccessUser:
		return "user"
	case AccessRepair:
		return "repair"
	case AccessAdmin:
		return "admin"
	case AccessUpgrade:
		return "upgrade"
	case AccessProbe:
		return "probe"
	case AccessPreview:
		return "preview"
	}
	return "unknown"
}

// route is one entry of the catalog: a ServeMux pattern relative to the
// application root and its access level.
type route struct {
	pattern string
	access  Access
}

// Paths of the routes the edge serves itself.
const (
	pathHealth        = "/health"
	pathReady         = "/ready"
	pathStatic        = "/static/"
	pathRealtime      = "/ws"
	pathRealtimeState = "/api/realtime/status"
	pathLogin         = "/login"
)

// m1Routes are the routes of the preview (M1 plan, section 1.3). The
// capabilities register their handlers on the edge's mux with exactly these
// patterns (wildcard names may differ); a catalog route without a handler
// answers 501 like a preview route, so a missing package never leaves a
// route open. Paths are relative to the application root: the reverse
// proxy strips APPLICATION_ROOT, as for the Python release.
var m1Routes = []route{
	// Probes and the edge's own routes.
	{"GET " + pathHealth, AccessProbe},
	{"GET " + pathReady, AccessProbe},
	{"GET " + pathStatic + "{path...}", AccessProbe},
	{"GET " + pathRealtime, AccessUpgrade},
	{"GET " + pathRealtimeState, AccessPublic},

	// Pages and forms.
	{"GET /{$}", AccessUser},
	{"GET /login", AccessPublic},
	{"POST /login", AccessPublic},
	{"POST /login/cancel", AccessPublic},
	{"GET /register", AccessPublic},
	{"POST /register", AccessPublic},
	{"POST /logout", AccessRepair},
	{"GET /change-password", AccessUser},
	{"POST /change-password", AccessUser},
	{"GET /security", AccessRepair},
	{"GET /settings", AccessRepair},
	{"GET /admin", AccessAdmin},

	// Account and settings.
	{"POST /api/account/preferences", AccessUser},
	{"GET /api/account/tour", AccessUser},
	{"POST /api/account/tour", AccessUser},
	{"GET /api/account/workspace-presets", AccessUser},
	{"PUT /api/account/workspace-presets", AccessUser},
	{"GET /api/account/recovery-check", AccessUser},
	{"GET /api/account/security-state", AccessRepair},
	{"GET /api/account/sessions", AccessUser},
	{"POST /api/account/sessions/revoke", AccessUser},

	// Step-up for the account and for administrators; one service.
	{"POST /api/account/step-up/intents", AccessUser},
	{"POST /api/account/step-up/password", AccessUser},
	{"POST /api/account/step-up/totp", AccessUser},
	{"POST /api/account/step-up/passkey/options", AccessUser},
	{"POST /api/account/step-up/passkey/verify", AccessUser},
	{"POST /api/account/mfa/disable", AccessUser},
	{"POST /api/step-up/intents", AccessAdmin},
	{"POST /api/step-up/password", AccessAdmin},
	{"POST /api/step-up/totp", AccessAdmin},
	{"POST /api/step-up/passkey/options", AccessAdmin},
	{"POST /api/step-up/passkey/verify", AccessAdmin},

	// TOTP.
	{"GET /api/totp/authenticators", AccessRepair},
	{"DELETE /api/totp/authenticators/{id}", AccessUser},
	{"POST /api/totp/enroll", AccessRepair},
	{"POST /api/totp/enroll/verify", AccessRepair},
	{"POST /api/totp/auth/verify", AccessPublic},

	// Recovery codes.
	{"POST /api/recovery-codes", AccessUser},
	{"POST /api/auth/recovery", AccessPublic},
	{"POST /api/auth/mfa/disable", AccessRepair},

	// Passkeys.
	{"GET /api/webauthn/credentials", AccessRepair},
	{"DELETE /api/webauthn/credentials/{id}", AccessUser},
	{"POST /api/webauthn/register/options", AccessRepair},
	{"POST /api/webauthn/register/verify", AccessRepair},
	{"POST /api/webauthn/auth/options", AccessPublic},
	{"POST /api/webauthn/auth/verify", AccessPublic},
	{"POST /api/webauthn/mfa", AccessUser},

	// Host keys.
	{"GET /api/host-keys", AccessUser},
	{"GET /api/host-keys/effective", AccessUser},
	{"GET /api/host-keys/{id}/deletion-impact", AccessUser},
	{"DELETE /api/host-keys/{id}", AccessUser},

	// Overview.
	{"GET /api/overview/status", AccessUser},
	{"GET /api/overview/reachability", AccessUser},
	{"PUT /api/overview/preferences", AccessUser},

	// Administration.
	{"GET /admin/api/users", AccessAdmin},
	{"POST /admin/api/users", AccessAdmin},
	{"GET /admin/api/security-features", AccessAdmin},
	{"GET /admin/api/security-features/{feature}/impact", AccessAdmin},
	{"POST /admin/api/security-features/{feature}", AccessAdmin},
}

// wildcardName matches the name of a ServeMux wildcard, so that patterns
// compare equal whatever their wildcards are called.
var wildcardName = regexp.MustCompile(`\{[^}.]*(\.\.\.)?\}`)

// patternKey normalises a ServeMux pattern: wildcard names are dropped,
// "{name...}" stays distinguishable from "{name}".
func patternKey(pattern string) string {
	return wildcardName.ReplaceAllStringFunc(pattern, func(w string) string {
		if strings.HasSuffix(w, "...}") {
			return "{...}"
		}
		if w == "{$}" {
			return w
		}
		return "{}"
	})
}

// adminGated reports whether ADMIN_PANEL_ENABLED=false hides a path: the
// administration pages and APIs and the administrator step-up, as in the
// Python release (hide_disabled_admin_panel and admin_required).
func adminGated(path string) bool {
	return path == "/admin" || strings.HasPrefix(path, "/admin/") || strings.HasPrefix(path, "/api/step-up/")
}

// samplePath returns a request path that the pattern's path matches, for
// checking whether a handler is registered. Wildcards become "x".
func samplePath(pattern string) (method, path string) {
	method, path, _ = strings.Cut(pattern, " ")
	path = wildcardName.ReplaceAllString(strings.ReplaceAll(path, "{$}", ""), "x")
	return method, path
}
