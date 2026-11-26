package commands_test

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/commands"
	"github.com/bifrost0x/webssh/internal/fault"
)

type refs map[string][]commands.Usage

func (r refs) SetUsages(_ context.Context, _ int64, id string) ([]commands.Usage, error) {
	return r[id], nil
}

func (r refs) CommandUsages(_ context.Context, _ int64, id string) ([]commands.Usage, error) {
	return r[id], nil
}

var _ commands.References = refs(nil)

// guardDelete is the reference protection of a set delete as CM1 builds
// it on the contract: in use answers in_use with at most 20 usages.
func guardDelete(ctx context.Context, r commands.References, userID int64, setID string) error {
	usages, err := r.SetUsages(ctx, userID, setID)
	if err != nil || len(usages) == 0 {
		return err
	}
	names := make([]string, 0, commands.MaxReferencedSetsShown)
	for _, u := range usages[:min(len(usages), commands.MaxReferencedSetsShown)] {
		names = append(names, u.Name)
	}
	return &fault.Error{Code: fault.InUse, Details: map[string]any{"usages": names}}
}

func TestReferenceProtection(t *testing.T) {
	t.Parallel()
	r := refs{"set-1": make([]commands.Usage, 25)}
	err := guardDelete(t.Context(), r, 1, "set-1")
	if !fault.Is(err, fault.InUse) || len(fault.DetailsOf(err)["usages"].([]string)) != 20 {
		t.Fatalf("guardDelete = %v", err)
	}
	if err := guardDelete(t.Context(), r, 1, "set-2"); err != nil {
		t.Fatalf("unused set = %v", err)
	}
}
