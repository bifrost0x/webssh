package httpapi

// Routes of the area "oidc" (ID2): OpenID Connect sign-in, links and step-up at the provider.
// ID2 moves each route it builds from oidcPreview to oidcBuilt with its
// access level; no other package edits this file.

var oidcBuilt = []route{}

var oidcPreview = []string{
	"GET /admin/api/users/{user_id}/oidc-identities",
	"DELETE /admin/api/users/{user_id}/oidc-identities/{identity_id}",
	"POST /admin/api/users/{user_id}/oidc-link",
	"GET /api/account/oidc",
	"POST /api/account/oidc/link/start",
	"POST /api/account/step-up/oidc/start",
	"GET /api/step-up/oidc/result",
	"POST /api/step-up/oidc/start",
	"GET /oidc/callback",
	"GET /oidc/login",
}
