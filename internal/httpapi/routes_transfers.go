package httpapi

// Routes of the area "transfers" (TR1): HTTP transfers.
// No other package edits this file.

// The upload streams its body to the file source (Handler.StreamBody).
var transfersBuilt = []route{
	{"GET /api/transfers/{token}/download", AccessUser},
	{"GET /api/transfers/{token}/folder-download", AccessUser},
	{"POST /api/transfers/{token}/upload", AccessUser},
}
