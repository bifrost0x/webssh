package httpapi

// Routes of the area "github" (ID3): GitHub sign-in, its configuration and the factor bootstrap.
// ID3 moves each route it builds from githubPreview to githubBuilt with its
// access level; no other package edits this file.

var githubBuilt = []route{}

var githubPreview = []string{
	"GET /admin/api/github-auth/config",
	"POST /admin/api/github-auth/config",
	"DELETE /api/account/github",
	"GET /api/account/github",
	"POST /api/account/github/link/start",
	"POST /api/account/step-up/bootstrap",
	"POST /api/account/step-up/github/start",
	"GET /auth/github/callback",
	"GET /auth/github/login",
}
