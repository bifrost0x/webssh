package fault

import "fmt"

// Codes of external identity and operation (M2 contracts). The Python
// release sends them with these spellings and the pages match on them.
const (
	// ActionUnconfirmed: an administrator action on a live connection
	// (disconnect, cancel a transfer) was sent, but its effect could not
	// be confirmed in time (app/operations.py).
	ActionUnconfirmed Code = "action_unconfirmed"
	// DeploymentLocked: the setting is fixed by an explicit environment
	// value and cannot be changed in the administration.
	DeploymentLocked Code = "deployment_locked"
	// OutOfRange: a numeric setting is outside its bounds; the answer also
	// carries the setting and its bounds as details.
	OutOfRange Code = "out_of_range"
	// LDAPValidationInProgress: the directory check of an LDAP session is
	// still running; the client retries after Retry-After.
	LDAPValidationInProgress Code = "ldap_validation_in_progress"
)

var operationCodes = map[Code]entry{
	ActionUnconfirmed:        {statusServiceUnavailable, "The action could not be confirmed."},
	DeploymentLocked:         {statusConflict, "The setting is controlled by the deployment configuration."},
	OutOfRange:               {statusBadRequest, "A value is out of range."},
	LDAPValidationInProgress: {statusServiceUnavailable, "Directory session validation is in progress."},
}

// The M2 code lists join the catalog once, before any lookup.
func init() {
	for _, part := range []map[Code]entry{operationCodes} {
		for c, e := range part {
			if _, dup := catalog[c]; dup {
				panic(fmt.Sprintf("fault: code %q is defined twice", c))
			}
			catalog[c] = e
		}
	}
}
