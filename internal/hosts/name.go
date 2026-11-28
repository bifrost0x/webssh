package hosts

import "github.com/bifrost0x/webssh/internal/fault"

var errDuplicateName = fault.New(fault.DuplicateName, "A saved host with this name already exists")

// foldName is the comparison form of a saved host's name: trimmed as the
// form trims it and case-folded as the Python import compared names.
func foldName(s string) string { return foldText(pyStrip(s)) }

// checkNameFree refuses a saved host whose name another saved host of the
// same user already has. index is the position of the host being updated,
// or -1 for a new one. Python stored duplicates and the migration keeps
// them, so an update that keeps the host's own name is never refused; only
// moving onto a name in use is. The caller runs it in the transaction that
// stores the host, so two concurrent saves cannot both pass.
func checkNameFree(profiles []record, index int, name string) error {
	folded := foldName(name)
	if index >= 0 && foldName(profiles[index].text("name")) == folded {
		return nil
	}
	for i := range profiles {
		if i != index && foldName(profiles[i].text("name")) == folded {
			return errDuplicateName
		}
	}
	return nil
}
