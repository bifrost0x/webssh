package httpapi

// Routes of the area "transfers" (TR1): HTTP transfers.
// TR1 moves each route it builds from transfersPreview to transfersBuilt with its
// access level; no other package edits this file.

var transfersBuilt = []route{}

var transfersPreview = []string{
	"GET /api/transfers/{token}/download",
	"GET /api/transfers/{token}/folder-download",
	"POST /api/transfers/{token}/upload",
}
