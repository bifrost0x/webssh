package httpapi

// Routes of the area "serverops" (HO1): server operations.
// HO1 moves each route it builds from serveropsPreview to serveropsBuilt with its
// access level; no other package edits this file.

var serveropsBuilt = []route{
	{"GET /api/server-operations/{session_id}", AccessUser},
	{"POST /api/server-operations/execute", AccessUser},
	{"POST /api/server-operations/intents", AccessUser},
	{"POST /api/server-operations/read", AccessUser},
}

var serveropsPreview = []string{}
