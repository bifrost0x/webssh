package legacy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

type failLaterStep struct {
	Step
	n     *atomic.Int32
	after int32
}

func (s failLaterStep) Write(ctx context.Context, tx *store.Tx, seal Sealer) error {
	if err := s.Step.Write(ctx, tx, seal); err != nil {
		return err
	}
	if s.Entity() == "E25" && s.n.Add(1) > s.after {
		return errors.New("injected failure after earlier accounts were written")
	}
	return nil
}

// A failure in a later account rolls back what the earlier accounts of
// the same and of earlier segments wrote: no database, legacy unchanged.
func TestLateAccountFailureLeavesNothing(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	o := m1Options(t, dir, M1{})
	o.Registry = restoreRegistry(t)
	var n atomic.Int32
	o.Registry.WrapSteps(func(s Step) Step { return failLaterStep{Step: s, n: &n, after: 5} })
	_, err := startClosed(o)
	se := assertStop(t, err, "E25")
	if n.Load() != 6 {
		t.Fatalf("failure after %d account writes", n.Load())
	}
	assertUntouched(t, dir, before)
	assertNoGoDatabase(t, dir)
	t.Logf("STOP: %v", se)
}
