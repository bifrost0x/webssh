package e2eseed

// skippedOwners names, for every seed part this build skips, the package
// of the M2 plan that adds its applier (M2 plan, section 4.8): the part
// becomes a step of Apply in the same change that merges the entity's
// capability, and leaves this table.
var skippedOwners = map[string]string{
	"admin_settings.automation_enabled":     "AU1",
	"test_hooks." + HookAutomationSSHPeer:   "AU1",
	"test_hooks." + HookSocketHerdrSessions: "HO1",
}

// SkippedOwner returns the package that will apply a skipped part.
func SkippedOwner(part string) (string, bool) {
	owner, ok := skippedOwners[part]
	return owner, ok
}
