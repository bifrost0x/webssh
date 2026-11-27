package legacy

import (
	"context"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// AddBackupState registers the steps of the area "backup" (OP1): the
// Python backup operations below BACKUP_TEMP_DIR (E39) and the restore
// status beside them (A10), which the M1 release lists as pending. Both
// stay where they are and are not taken over (migration specification,
// entity table): Go keeps its own operations and restore journal, a
// restore of `rollback.zip` or `*-pre-rotation-*.zip` goes through the
// restore of Python backups (5.6), and an unfinished Python restore has
// already stopped the migration (A10, restorestatus.go).
func AddBackupState(r *Registry, backupTempDir string) error {
	return errors.Join(r.Add(GroupInventory, func() Step {
		return &backupStateStep{entity: "E39", count: func(src *Source) (int, error) { return backupOperations(backupTempDir, src) },
			note: "Python backup operations below BACKUP_TEMP_DIR stay there and are not taken over; " +
				"a rollback or pre-rotation archive among them can be restored with `webssh backup restore --recovery-snapshot`"}
	}), r.Add(GroupInventory, func() Step {
		return &backupStateStep{entity: "A10", count: func(src *Source) (int, error) { return restoreStatusFiles(backupTempDir, src) },
			note: "the finished Python restore status in BACKUP_TEMP_DIR is not taken over; Go keeps its own restore journal"}
	}))
}

// backupStateStep reads how many entries of entity the legacy side has;
// it writes nothing and verifies nothing, because nothing is taken over.
type backupStateStep struct {
	entity string
	count  func(src *Source) (int, error)
	note   string
	n      int
}

func (s *backupStateStep) Entity() string { return s.entity }

func (*backupStateStep) Version() int { return 1 }

func (s *backupStateStep) Read(_ context.Context, src *Source) error {
	n, err := s.count(src)
	if err != nil {
		return fmt.Errorf("legacy: count %s: %w", s.entity, err)
	}
	s.n = n
	return nil
}

func (*backupStateStep) Write(context.Context, *store.Tx, Sealer) error { return nil }

func (*backupStateStep) Verify(context.Context, *store.Tx, Opener) error { return nil }

func (s *backupStateStep) Report() StepReport {
	r := StepReport{Entity: s.entity, Version: 1, Read: s.n}
	if s.n > 0 {
		r.Notes = []string{s.note}
	}
	return r
}
