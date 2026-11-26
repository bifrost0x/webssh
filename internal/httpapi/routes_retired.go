package httpapi

// Routes of the area "retired" (FE1): routes without a caller (D-13); FE1 decides their final answer.
// FE1 moves each route it builds from retiredPreview to retiredBuilt with its
// access level; no other package edits this file.

var retiredBuilt = []route{}

var retiredPreview = []string{
	"POST /api/totp/disable",
}
