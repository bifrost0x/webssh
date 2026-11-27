package httpapi

// Routes of the area "github" (ID3): GitHub sign-in, its configuration and the factor bootstrap.
// No other package edits this file.

var githubBuilt = []route{
	// The redirect and its callback run before sign-in; a link callback
	// reads the session the edge puts into the context.
	{"GET /auth/github/login", AccessPublic},
	{"GET /auth/github/callback", AccessPublic},
	{"GET /api/account/github", AccessUser},
	{"DELETE /api/account/github", AccessUser},
	{"POST /api/account/github/link/start", AccessUser},
	{"POST /api/account/step-up/github/start", AccessUser},
	{"POST /api/account/step-up/bootstrap", AccessUser},
	{"GET /admin/api/github-auth/config", AccessAdmin},
	{"POST /admin/api/github-auth/config", AccessAdmin},
}
