package httpapi

// Routes of the area "transfers" (TR1): HTTP transfers.
// TR1 moves each route it builds from transfersPreview to transfersBuilt with its
// access level; no other package edits this file.

// The upload streams its body to the file source (AccessUserStream).
var transfersBuilt = []route{
	{"GET /api/transfers/{token}/download", AccessUser},
	{"GET /api/transfers/{token}/folder-download", AccessUser},
	{"POST /api/transfers/{token}/upload", AccessUserStream},
}

var transfersPreview = []string{}
