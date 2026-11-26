package httpapi

// Routes of the area "oidc" (ID2): OpenID Connect sign-in, links and step-up at the provider.
// ID2 moves each route it builds from oidcPreview to oidcBuilt with its
// access level; no other package edits this file.

var oidcBuilt = []route{
	{"GET /oidc/login", AccessPublic},
	{"GET /oidc/callback", AccessPublic},
	{"GET /api/account/oidc", AccessUser},
	{"POST /api/account/oidc/link/start", AccessUser},
	{"POST /api/account/step-up/oidc/start", AccessUser},
	// The status poll of a step-up proven at a provider; OIDC needs it
	// first (C-IDP-05), GitHub uses the same route.
	{"POST /api/account/step-up/status", AccessUser},
	{"POST /api/step-up/oidc/start", AccessAdmin},
	{"GET /api/step-up/oidc/result", AccessAdmin},
	{"GET /admin/api/users/{user_id}/oidc-identities", AccessAdmin},
	{"DELETE /admin/api/users/{user_id}/oidc-identities/{identity_id}", AccessAdmin},
	{"POST /admin/api/users/{user_id}/oidc-link", AccessAdmin},
}

var oidcPreview = []string{}
