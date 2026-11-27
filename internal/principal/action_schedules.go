package principal

// Step-up action of the automation schedules (AU2).
const (
	// ActionAutomationSchedule approves a reviewed schedule: the target is
	// the token of the schedule intent, which holds the frozen runbook and
	// targets. The name is the one the page sends (static/js/automation.js).
	ActionAutomationSchedule Action = "automation.schedule"
)

var scheduleActions = []Action{ActionAutomationSchedule}
