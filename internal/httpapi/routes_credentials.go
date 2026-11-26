package httpapi

// Routes of the area "credentials" (VA1): saved credentials and the legacy automation vault.
// VA1 moves each route it builds from credentialsPreview to credentialsBuilt with its
// access level; no other package edits this file.

var credentialsBuilt = []route{}

var credentialsPreview = []string{
	"POST /api/automation/vault/apply",
	"POST /api/automation/vault/intents",
	"POST /api/automation/vault/lock",
	"POST /api/credentials",
	"DELETE /api/credentials/{rid}",
	"PATCH /api/credentials/{rid}",
	"POST /api/credentials/apply",
	"POST /api/credentials/assign",
	"POST /api/credentials/authorize-target",
	"POST /api/credentials/create-for-resource",
	"POST /api/credentials/import-legacy",
	"POST /api/credentials/intents",
	"POST /api/credentials/lock",
	"GET /api/credentials/state",
	"GET /credentials",
}
