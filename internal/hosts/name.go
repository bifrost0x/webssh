package hosts

import (
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/naming"
)

var (
	errDuplicateName      = fault.New(fault.DuplicateName, "A saved host with this name already exists")
	errDuplicateJumpName  = fault.New(fault.DuplicateName, "A jump host with this name already exists")
	errDuplicateSOCKSName = fault.New(fault.DuplicateName, "A SOCKS proxy with this name already exists")
)

// foldName is the comparison form of a record's name (internal/naming).
func foldName(s string) string { return naming.Key(s) }

// checkNameFree refuses a record whose name another record of the same
// list already has. own are the positions of the record being updated
// (none for a new one). Python stored duplicates and the migration keeps
// them, so an update that keeps the record's own name is never refused.
// The caller runs it in the transaction that stores the record, so two
// concurrent saves cannot both pass.
func checkNameFree(records []record, own []int, name string, taken error) error {
	names := make([]string, len(records))
	for i := range records {
		names[i] = records[i].text("name")
	}
	if naming.Taken(names, own, name) {
		return taken
	}
	return nil
}

// positions are the indexes of the records with id (Python updates every
// match).
func positions(records []record, id string) []int {
	var out []int
	for i := range records {
		if v, ok := records[i].str("id"); ok && v == id {
			out = append(out, i)
		}
	}
	return out
}

// ownPositions are the positions an upsert of requested replaces.
func ownPositions(records []record, update bool, requested jsontext.Value) []int {
	if !update {
		return nil
	}
	id, _ := asString(requested)
	return positions(records, id)
}
