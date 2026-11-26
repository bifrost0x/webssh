package httpapi

// Routes of the area "accounts" (ID4): account administration, the recovery sign-in and the step-up status.
// ID4 moves each route it builds from accountsPreview to accountsBuilt with its
// access level; no other package edits this file.

var accountsBuilt = []route{}

var accountsPreview = []string{
	"POST /admin/api/users/{user_id}/{action}",
	"DELETE /admin/api/users/{user_id}/mfa",
	"POST /admin/api/users/{user_id}/recovery",
	"POST /api/account/step-up/status",
	"POST /login/recovery",
}
