package principal

// Step-up actions of the automation (contract of AU1,
// docs/architecture/m2-contracts.md), named as in the Python
// release.
const (
	// ActionAutomationRun starts a reviewed run; the target is the review
	// intent, which binds the grant to the user, the session, the runbook
	// and the targets.
	ActionAutomationRun Action = "automation.run"
)

var automationActions = []Action{ActionAutomationRun}
