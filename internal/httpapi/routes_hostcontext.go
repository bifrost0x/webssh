package httpapi

// Routes of the area "hostcontext" (HO3): global host trust, host context and profile exchange.
// No other package edits this file.

var hostcontextBuilt = []route{
	{"GET /admin/api/host-keys", AccessAdmin},
	{"POST /admin/api/host-keys", AccessAdmin},
	{"DELETE /admin/api/host-keys/{entry_id}", AccessAdmin},
	{"GET /api/profiles/{profile_id}/context", AccessUser},
	{"PUT /api/profiles/{profile_id}/context", AccessUser},
	{"GET /api/profiles/exchange", AccessUser},
	{"POST /api/profiles/exchange", AccessUser},
	{"POST /api/profiles/exchange/preview", AccessUser},
}
