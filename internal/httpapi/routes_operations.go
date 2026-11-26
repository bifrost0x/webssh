package httpapi

// Routes of the area "operations" (OP3): audit, instance operations, application settings and the support report.
// OP3 moves each route it builds from operationsPreview to operationsBuilt with its
// access level; no other package edits this file.

var operationsBuilt = []route{}

var operationsPreview = []string{
	"GET /admin/api/audit",
	"GET /admin/api/audit/export",
	"POST /admin/api/audit/retention",
	"GET /admin/api/operations",
	"POST /admin/api/operations/connections/{connection_ref}/disconnect",
	"GET /admin/api/operations/details",
	"POST /admin/api/operations/sessions/{session_ref}/disconnect",
	"POST /admin/api/operations/transfers/{transfer_id}/cancel",
	"GET /admin/api/settings",
	"POST /admin/api/settings",
	"POST /api/account/support-report",
}
