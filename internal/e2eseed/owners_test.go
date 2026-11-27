package e2eseed

import (
	"slices"
	"testing"
)

// Every part the build can skip has an owner, and the table lists nothing
// the build applies.
func TestSkippedPartsHaveOwners(t *testing.T) {
	t.Parallel()
	on := true
	s := &Seed{
		AdminSettings: AdminSettings{AutomationEnabled: &on},
		Commands:      []OwnedEntry{{}},
		CommandSets:   []OwnedEntry{{}},
		TestHooks:     []Hook{{Name: HookAutomationSSHPeer}, {Name: HookOutboundSSHGuard}},
	}
	parts := s.skipped()
	for _, part := range parts {
		if _, ok := SkippedOwner(part); !ok {
			t.Errorf("skipped part %s has no owner", part)
		}
	}
	for part := range skippedOwners {
		if !slices.Contains(parts, part) {
			t.Errorf("owner table lists %s, which the build does not skip", part)
		}
	}
}
