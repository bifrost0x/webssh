package fault

// Codes of automation (app/automation_routes.py); the spelling stays.
const (
	// AutomationDisabled: an administrator turned automation off.
	AutomationDisabled Code = "disabled"
)

var automationCodes = map[Code]entry{
	AutomationDisabled: {statusForbidden, "Automation is turned off."},
}
