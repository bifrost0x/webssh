package httpapi

// Routes of the area "discovery" (HO2): discovery scans and the reachability check.
// No other package edits this file.

var discoveryBuilt = []route{
	{"POST /api/discovery/scans", AccessUser},
	{"DELETE /api/discovery/scans/{scan_id}", AccessUser},
	{"GET /api/discovery/scans/{scan_id}", AccessUser},
	{"POST /api/overview/reachability", AccessUser},
}
