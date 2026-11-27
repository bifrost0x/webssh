package httpapi

// Routes of the area "ldap" (ID1): LDAP and Active Directory sign-in, links and step-up.
// No other package edits this file.

var ldapBuilt = []route{
	{"GET /admin/api/ldap/status", AccessAdmin},
	{"DELETE /admin/api/users/{user_id}/ldap-identities/{identity_id}", AccessAdmin},
	{"GET /admin/api/users/{user_id}/ldap-identity", AccessAdmin},
	{"POST /admin/api/users/{user_id}/ldap-link", AccessAdmin},
	{"POST /api/account/step-up/ldap", AccessUser},
	{"POST /login/ldap", AccessPublic},
}
