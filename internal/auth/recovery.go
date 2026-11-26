package auth

import "strings"

// RecoveryRouteAllowed is recovery_route_allowed: the HTTP routes a
// recovery session may use, all of them for factor repair or signing out.
// path is relative to APPLICATION_ROOT. The edge refuses every other route
// for a principal with Recovery set.
func RecoveryRouteAllowed(method, path string) bool {
	method = strings.ToUpper(method)
	switch {
	case path == "/security" || path == "/settings" || path == "/logout" || strings.HasPrefix(path, "/static/"):
		return true
	case path == "/api/webauthn/register/options" || path == "/api/webauthn/register/verify":
		return method == "POST"
	case path == "/api/webauthn/credentials", path == "/api/totp/authenticators":
		return method == "GET"
	case path == "/api/account/security-state":
		return method == "GET"
	case path == "/api/totp/enroll" || path == "/api/totp/enroll/verify":
		return method == "POST"
	case path == "/api/totp/disable" || path == "/api/auth/mfa/disable":
		return method == "POST"
	}
	return false
}
