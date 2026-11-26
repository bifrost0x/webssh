package httpapi

// Routes of the area "serverops" (HO1): server operations.
// HO1 moves each route it builds from serveropsPreview to serveropsBuilt with its
// access level; no other package edits this file.

var serveropsBuilt = []route{}

var serveropsPreview = []string{
	"GET /api/server-operations/{session_id}",
	"POST /api/server-operations/execute",
	"POST /api/server-operations/intents",
	"POST /api/server-operations/read",
}
