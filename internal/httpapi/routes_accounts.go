package httpapi

// Routes of the area "accounts" (ID4): account administration and the
// recovery sign-in. The step-up status is built with OIDC (routes_oidc.go).
// No other package edits this file.

var accountsBuilt = []route{
	{"POST /admin/api/users/{user_id}/{action}", AccessAdmin},
	{"DELETE /admin/api/users/{user_id}/mfa", AccessAdmin},
	{"POST /admin/api/users/{user_id}/recovery", AccessAdmin},
	{"POST /login/recovery", AccessPublic},
}
