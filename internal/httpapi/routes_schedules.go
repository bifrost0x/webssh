package httpapi

// Routes of the area "schedules" (AU2): automation schedules.
// AU2 moves each route it builds from schedulesPreview to schedulesBuilt with its
// access level; no other package edits this file.

var schedulesBuilt = []route{}

var schedulesPreview = []string{
	"GET /api/automation/schedules",
	"POST /api/automation/schedules",
	"DELETE /api/automation/schedules/{schedule_id}",
	"POST /api/automation/schedules/{schedule_id}/pause",
	"POST /api/automation/schedules/{schedule_id}/preview-run",
	"POST /api/automation/schedules/preview",
}
