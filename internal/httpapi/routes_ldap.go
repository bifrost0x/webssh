package httpapi

// Routes of the area "ldap" (ID1): LDAP and Active Directory sign-in, links and step-up.
// ID1 moves each route it builds from ldapPreview to ldapBuilt with its
// access level; no other package edits this file.

var ldapBuilt = []route{}

var ldapPreview = []string{
	"GET /admin/api/ldap/status",
	"DELETE /admin/api/users/{user_id}/ldap-identities/{identity_id}",
	"GET /admin/api/users/{user_id}/ldap-identity",
	"POST /admin/api/users/{user_id}/ldap-link",
	"POST /api/account/step-up/ldap",
	"POST /login/ldap",
}
