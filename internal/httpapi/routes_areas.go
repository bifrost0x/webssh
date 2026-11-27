package httpapi

import (
	"fmt"
	"net/http"
)

// area is one part of the route catalog that one M2 package built. Each
// area has its own file routes_<name>.go, so packages built in parallel
// never edit the same lines (M2 plan, section 4.7).
type area struct {
	name  string
	owner string // the package of the M2 plan that built it
	built []route
}

// areas are the parts of the catalog after the routes of M1, in a fixed order.
var areas = []area{
	{"ldap", "ID1", ldapBuilt},
	{"oidc", "ID2", oidcBuilt},
	{"github", "ID3", githubBuilt},
	{"accounts", "ID4", accountsBuilt},
	{"backup", "OP1", backupBuilt},
	{"operations", "OP3", operationsBuilt},
	{"hostcontext", "HO3", hostcontextBuilt},
	{"discovery", "HO2", discoveryBuilt},
	{"serverops", "HO1", serveropsBuilt},
	{"credentials", "VA1", credentialsBuilt},
	{"automation", "AU1", automationBuilt},
	{"schedules", "AU2", schedulesBuilt},
	{"transfers", "TR1", transfersBuilt},
	{"files", "FS1", filesBuilt},
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

// droppedRoutes are routes of the Python release that this server does
// not have, each with its decision. They answer 404 like any unknown
// route; the migration notice lists them. Together with catalogRoutes
// they cover every route of the Python release;
// TestRouteCatalogCoversPython checks that against the Flask url_map in
// testdata/python-routes.json.
var droppedRoutes = map[string]string{
	// No caller since 3.0: the passphrase vault was replaced by saved
	// passwords; the import of an old vault stays (D-06).
	"POST /api/automation/vault/apply":   "D-06",
	"POST /api/automation/vault/intents": "D-06",
	"POST /api/automation/vault/lock":    "D-06",
	"POST /api/credentials/apply":        "D-06",
	"POST /api/credentials/lock":         "D-06",
	// No caller: TOTP is turned off through the one MFA switch of the
	// settings page (D-13).
	"POST /api/totp/disable": "D-13",
}

// DisableArea answers every route of the named area that has no handler
// with 404, for an area the configuration turns off: the OIDC routes
// without OIDC_ENABLED, which the Python release answers with 404 too.
// Routes the area shares with another area keep their handler. It must
// be called before Finish.
func (h *Handler) DisableArea(name string) error {
	for _, a := range areas {
		if a.name != name {
			continue
		}
		for _, rt := range a.built {
			if !h.registered(rt.pattern) {
				h.mux.Handle(rt.pattern, http.HandlerFunc(h.unwired))
			}
		}
		return nil
	}
	return fmt.Errorf("httpapi: no route area %q", name)
}
