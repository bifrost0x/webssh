package httpapi

// Routes of the area "serverops" (HO1): server operations.
// No other package edits this file.

var serveropsBuilt = []route{
	{"GET /api/server-operations/{session_id}", AccessUser},
	{"POST /api/server-operations/execute", AccessUser},
	{"POST /api/server-operations/intents", AccessUser},
	{"POST /api/server-operations/read", AccessUser},
}
