package httpapi

// Routes of the area "operations" (OP3): audit, instance operations, application settings and the support report.
// No other package edits this file.

var operationsBuilt = []route{
	{"GET /admin/api/audit", AccessAdmin},
	{"GET /admin/api/audit/export", AccessAdmin},
	{"POST /admin/api/audit/retention", AccessAdmin},
	{"GET /admin/api/operations", AccessAdmin},
	{"POST /admin/api/operations/connections/{connection_ref}/disconnect", AccessAdmin},
	{"GET /admin/api/operations/details", AccessAdmin},
	{"POST /admin/api/operations/sessions/{session_ref}/disconnect", AccessAdmin},
	{"POST /admin/api/operations/transfers/{transfer_id}/cancel", AccessAdmin},
	{"GET /admin/api/settings", AccessAdmin},
	{"POST /admin/api/settings", AccessAdmin},
	{"POST /api/account/support-report", AccessUser},
}
