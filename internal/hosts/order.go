package hosts

import (
	"encoding/json/jsontext"
	"slices"
)

// Groups are flat and named by the stripped text; two names that differ
// only in case are one group. Inside a group the hosts are ordered by
// sort_order and then by list position; a group with a host that has no
// valid sort_order keeps list order (legacy stores).

func recordGroupKey(r *record) string { return groupKey(r.text("group")) }

// orderedGroup is _ordered_group: the indexes of the members of the group
// with key, in their order, without the record with excludeID.
func orderedGroup(records []record, key string, excludeID *string) []int {
	var members []int
	allValid := true
	for i := range records {
		r := &records[i]
		if recordGroupKey(r) != key {
			continue
		}
		if excludeID != nil {
			if id, ok := r.str("id"); ok && id == *excludeID {
				continue
			}
		}
		members = append(members, i)
		if v, ok := r.get("sort_order"); !ok || !sortOrderValid(v) {
			allValid = false
		}
	}
	if !allValid {
		return members
	}
	slices.SortStableFunc(members, func(a, b int) int {
		av, _ := records[a].get("sort_order")
		bv, _ := records[b].get("sort_order")
		return compareSortOrder(av, bv)
	})
	return members
}

// nextSortOrder is _next_sort_order.
func nextSortOrder(records []record, key string, excludeID *string) int64 {
	return int64(len(orderedGroup(records, key, excludeID)))
}

// placement is one entry of the organization list of a move
// acknowledgement: id, group (an empty string for none), sort_order (0
// when absent) and, after a successful move, updated_at.
type placement struct {
	id                   string
	group, sort, updated jsontext.Value
}

func placementsOf(records []record, withUpdated bool) []placement {
	out := []placement{}
	for i := range records {
		r := &records[i]
		id, ok := r.str("id")
		if !ok {
			continue
		}
		pl := placement{id: id, group: jsonString(""), sort: jsonInt(0)}
		if v, ok := r.get("group"); ok {
			pl.group = v
		}
		if v, ok := r.get("sort_order"); ok {
			pl.sort = v
		}
		if v, ok := r.get("updated_at"); ok && withUpdated {
			pl.updated = v
		}
		out = append(out, pl)
	}
	return out
}
