package httpapi

// area is one part of the route catalog that one M2 package completes.
// Each area has its own file routes_<name>.go with the routes it has built
// and the routes that still answer 501, so packages built in parallel
// never edit the same lines (M2 plan, section 4.7).
type area struct {
	name    string
	owner   string // the package of the M2 plan that builds it
	built   []route
	preview []string
}

// areas are the parts of the catalog after the routes of M1, in a fixed order.
var areas = []area{
	{"ldap", "ID1", ldapBuilt, ldapPreview},
	{"oidc", "ID2", oidcBuilt, oidcPreview},
	{"github", "ID3", githubBuilt, githubPreview},
	{"accounts", "ID4", accountsBuilt, accountsPreview},
	{"retired", "FE1", retiredBuilt, retiredPreview},
	{"backup", "OP1", backupBuilt, backupPreview},
	{"operations", "OP3", operationsBuilt, operationsPreview},
	{"hostcontext", "HO3", hostcontextBuilt, hostcontextPreview},
	{"discovery", "HO2", discoveryBuilt, discoveryPreview},
	{"serverops", "HO1", serveropsBuilt, serveropsPreview},
	{"credentials", "VA1", credentialsBuilt, credentialsPreview},
	{"automation", "AU1", automationBuilt, automationPreview},
	{"schedules", "AU2", schedulesBuilt, schedulesPreview},
	{"transfers", "TR1", transfersBuilt, transfersPreview},
}

// catalogRoutes are the routes with an access level: M1 and every built
// area route.
func catalogRoutes() []route {
	out := append([]route(nil), m1Routes...)
	for _, a := range areas {
		out = append(out, a.built...)
	}
	return out
}

// previewRoutes are the routes of the Python release that this build does
// not have yet. Each answers 501 not_available_in_preview before anything
// reads the request: no session lookup, no body, no handler. Together with
// catalogRoutes they cover every route of the Python release;
// TestRouteCatalogCoversPython checks that against the Flask url_map in
// testdata/python-routes.json.
func previewRoutes() []string {
	var out []string
	for _, a := range areas {
		out = append(out, a.preview...)
	}
	return out
}
