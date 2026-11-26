package httpapi

// Routes of the area "discovery" (HO2): discovery scans and the reachability check.
// HO2 moves each route it builds from discoveryPreview to discoveryBuilt with its
// access level; no other package edits this file.

var discoveryBuilt = []route{}

var discoveryPreview = []string{
	"POST /api/discovery/scans",
	"DELETE /api/discovery/scans/{scan_id}",
	"GET /api/discovery/scans/{scan_id}",
	"POST /api/overview/reachability",
}
