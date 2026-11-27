package httpapi

// Routes of the area "schedules" (AU2): automation schedules.
// No other package edits this file.

var schedulesBuilt = []route{
	{"GET /api/automation/schedules", AccessUser},
	{"POST /api/automation/schedules", AccessUser},
	{"DELETE /api/automation/schedules/{schedule_id}", AccessUser},
	{"POST /api/automation/schedules/{schedule_id}/pause", AccessUser},
	{"POST /api/automation/schedules/{schedule_id}/preview-run", AccessUser},
	{"POST /api/automation/schedules/preview", AccessUser},
}
