package httpapi

// Routes of the area "credentials" (VA1): saved credentials.
// No other package edits this file.

var credentialsBuilt = []route{
	{"GET /credentials", AccessUser},
	{"GET /api/credentials/state", AccessUser},
	{"POST /api/credentials/intents", AccessUser},
	{"POST /api/credentials", AccessUser},
	{"PATCH /api/credentials/{rid}", AccessUser},
	{"DELETE /api/credentials/{rid}", AccessUser},
	{"POST /api/credentials/assign", AccessUser},
	{"POST /api/credentials/import-legacy", AccessUser},
	{"POST /api/credentials/authorize-target", AccessUser},
	{"POST /api/credentials/create-for-resource", AccessUser},
}
