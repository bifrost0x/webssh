package legacy

import (
	"context"
	"testing"
)

// M1 of the review: what E28 does not migrate (directories and
// command-set references, contexts of deleted profiles) is pending with
// its number, so the purge guard sees it; the notes are migrated.
func TestM1HostContextPartlyPending(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	var found *Pending
	for i, p := range m.report.Pending {
		if p.Entity == "E28" {
			found = &m.report.Pending[i]
		}
	}
	if found == nil || found.Phase != "B5" || found.Count != 1 {
		t.Fatalf("E28 pending: %+v", found)
	}
	if e := m.entity(t, "E28"); e.Written != 1 {
		t.Fatalf("E28 notes: %+v", e)
	}
	kinds := map[string]bool{}
	for _, c := range m.report.Coverage {
		if c.Entity == "E28" {
			kinds[c.Kind] = true
		}
	}
	if !kinds[CoverStep] || !kinds[CoverPending] {
		t.Fatalf("coverage of E28: %v", kinds)
	}
}

func TestRegistryPartlyPending(t *testing.T) {
	t.Parallel()
	count := func(context.Context, *Source) (int, error) { return 0, nil }
	r := NewRegistry()
	if err := r.PartlyPending("E28", "B5", count); err == nil {
		t.Fatal("partly pending without a step")
	}
	if err := r.Add(GroupHostContext, func() Step { return &hostNotesStep{} }); err != nil {
		t.Fatal(err)
	}
	if err := r.PartlyPending("E28", "", count); err == nil {
		t.Fatal("no phase accepted")
	}
	if err := r.PartlyPending("E28", "B5", count); err != nil {
		t.Fatal(err)
	}
	if err := r.PartlyPending("E28", "B5", count); err == nil {
		t.Fatal("pending twice")
	}
}
