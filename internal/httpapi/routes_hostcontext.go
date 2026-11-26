package httpapi

// Routes of the area "hostcontext" (HO3): global host trust, host context and profile exchange.
// HO3 moves each route it builds from hostcontextPreview to hostcontextBuilt with its
// access level; no other package edits this file.

var hostcontextBuilt = []route{}

var hostcontextPreview = []string{
	"GET /admin/api/host-keys",
	"POST /admin/api/host-keys",
	"DELETE /admin/api/host-keys/{entry_id}",
	"GET /api/profiles/{profile_id}/context",
	"PUT /api/profiles/{profile_id}/context",
	"GET /api/profiles/exchange",
	"POST /api/profiles/exchange",
	"POST /api/profiles/exchange/preview",
}
