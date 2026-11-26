package legacy

import (
	"context"
	"errors"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// failingStep wraps a step of the M1 registry. When armed for its entity
// it runs the real Write and then fails or calls crash, so the failure
// lands after the step has written into the staging transaction.
type failingStep struct {
	Step
	target string
	crash  func()
}

var errInjected = errors.New("injected failure")

func (s *failingStep) Write(ctx context.Context, tx *store.Tx, seal Sealer) error {
	if err := s.Step.Write(ctx, tx, seal); err != nil {
		return err
	}
	if s.Entity() != s.target {
		return nil
	}
	if s.crash != nil {
		s.crash()
	}
	return errInjected
}

func m1Entities(t *testing.T) []string {
	t.Helper()
	r := m1Registry(t, M1{Persistent: &testPersistent{}})
	var out []string
	for _, s := range r.ordered() {
		out = append(out, s.entity)
	}
	return out
}

// A failure in any step, after it wrote, stops the migration: no Go
// database, no staging directory, the legacy data unchanged, and the next
// start migrates completely.
func TestM1FailureInEveryStepLeavesNothing(t *testing.T) {
	t.Parallel()
	for _, entity := range m1Entities(t) {
		t.Run(entity, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			before := legacySnapshot(t, dir)
			m := M1{Persistent: &testPersistent{}}
			m.wrap = func(s Step) Step { return &failingStep{Step: s, target: entity} }
			_, err := startClosed(m1Options(t, dir, m))
			se := assertStop(t, err, entity)
			if !errors.Is(se, errInjected) {
				t.Fatalf("cause: %v", se)
			}
			assertUntouched(t, dir, before)
			assertNoGoDatabase(t, dir)
			st, err := startClosed(m1Options(t, dir, M1{Persistent: &testPersistent{}}))
			if err != nil || !st.Migrated {
				t.Fatalf("next start: %+v, %v", st, err)
			}
		})
	}
}
