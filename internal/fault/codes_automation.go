package fault

// Codes of automation (app/automation_routes.py); the spelling stays.
const (
	// AutomationDisabled: an administrator turned automation off.
	AutomationDisabled Code = "disabled"
	// HostKeyRequired: a target's host key is not verified yet.
	HostKeyRequired Code = "host_key_required"
	// UnsupportedTarget: a target signs in in a way automation cannot.
	UnsupportedTarget Code = "unsupported_target"
	// KeyUnavailable: a target's SSH key cannot be read.
	KeyUnavailable Code = "key_unavailable"
)

var automationCodes = map[Code]entry{
	AutomationDisabled: {statusForbidden, "Automation is turned off."},
	HostKeyRequired:    {statusConflict, "Verify the host key in an interactive connection first."},
	UnsupportedTarget:  {statusBadRequest, "This host cannot be used for automation."},
	KeyUnavailable:     {statusBadRequest, "The SSH key of a host cannot be read."},
}
