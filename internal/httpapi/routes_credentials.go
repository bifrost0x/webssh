package httpapi

// Routes of the area "credentials" (VA1): saved credentials and the legacy automation vault.
// VA1 moves each route it builds from credentialsPreview to credentialsBuilt with its
// access level; no other package edits this file.

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

// credentialsPreview are the passphrase vault routes, which have no caller
// since the passphrase vault was replaced by saved passwords; decision
// D-06 drops them, and they answer 501 until the retired routes get their
// final answer.
var credentialsPreview = []string{
	"POST /api/automation/vault/apply",
	"POST /api/automation/vault/intents",
	"POST /api/automation/vault/lock",
	"POST /api/credentials/apply",
	"POST /api/credentials/lock",
}
