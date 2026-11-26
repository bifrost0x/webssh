package httpapi

// Routes of the area "automation" (AU1): automation runbooks and runs.
// AU1 moves each route it builds from automationPreview to automationBuilt with its
// access level; no other package edits this file.

var automationBuilt = []route{}

var automationPreview = []string{
	"POST /api/automation/preview",
	"POST /api/automation/runbooks",
	"DELETE /api/automation/runbooks/{book_id}",
	"GET /api/automation/runs",
	"DELETE /api/automation/runs/{run_id}",
	"POST /api/automation/runs/{run_id}/cancel",
	"GET /api/automation/runs/{run_id}/export",
	"POST /api/automation/runs/clear",
	"POST /api/automation/start",
	"GET /api/automation/state",
	"GET /automation",
}
