package httpapi

// Routes of the area "automation" (AU1): automation runbooks and runs.
// AU1 moves each route it builds from automationPreview to automationBuilt with its
// access level; no other package edits this file.

var automationBuilt = []route{
	{"GET /automation", AccessUser},
	{"GET /api/automation/state", AccessUser},
	{"POST /api/automation/runbooks", AccessUser},
	{"DELETE /api/automation/runbooks/{book_id}", AccessUser},
	{"POST /api/automation/preview", AccessUser},
	{"POST /api/automation/start", AccessUser},
	{"GET /api/automation/runs", AccessUser},
	{"POST /api/automation/runs/{run_id}/cancel", AccessUser},
	{"DELETE /api/automation/runs/{run_id}", AccessUser},
	{"POST /api/automation/runs/clear", AccessUser},
	{"GET /api/automation/runs/{run_id}/export", AccessUser},
}

var automationPreview = []string{}
