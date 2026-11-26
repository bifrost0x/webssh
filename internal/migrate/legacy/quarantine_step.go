package legacy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/store"
)

// quarantineStep accounts for entity E33: the directories of deleted
// accounts below deleted_users/ stay where they are and are never
// associated with the account that now holds the same id (4.1). Each is
// recorded in accounts_quarantine, and the id floor is raised past every
// former id, so Go never hands out such an id again.
type quarantineStep struct {
	dirs  []quarantined
	other []string // entries that are not named like a deleted account
	// implausible are named like a deleted account with an id above
	// maxDirectoryID; they stay in place without an index entry.
	implausible []string
	found       time.Time
}

type quarantined struct {
	path string
	id   int64
}

func (*quarantineStep) Entity() string { return "E33" }

func (*quarantineStep) Version() int { return 1 }

func (s *quarantineStep) Read(_ context.Context, src *Source) error {
	names, err := src.QuarantinedAccounts()
	if err != nil {
		return err
	}
	s.found = time.Now().UTC()
	for _, n := range names {
		id, ok := quarantinedID(n)
		if ok && id > maxDirectoryID {
			s.implausible = append(s.implausible, "deleted_users/"+n)
			continue
		}
		if !ok {
			// Python never reads deleted_users/; an entry named otherwise is
			// not an account's data and stays as it is.
			s.other = append(s.other, "deleted_users/"+n)
			continue
		}
		s.dirs = append(s.dirs, quarantined{path: "deleted_users/" + n, id: id})
	}
	return nil
}

// maxDirectoryID bounds the ids taken from directory names for the id
// floor. Python's account ids come from SQLite and stay far below it; a
// larger number in a directory name is not an id Python handed out, and
// raising the floor to it would leave no ids for new accounts (or
// overflow). Such a directory stays in place and the report names it.
const maxDirectoryID = math.MaxInt32

// quarantinedID parses user_<id>_<hex32> (app/user_lifecycle.py).
func quarantinedID(name string) (int64, bool) {
	rest, ok := strings.CutPrefix(name, "user_")
	if !ok {
		return 0, false
	}
	idText, suffix, ok := strings.Cut(rest, "_")
	id, err := strconv.ParseInt(idText, 10, 64)
	return id, ok && err == nil && id > 0 && isLowerHex(suffix, 32)
}

func (s *quarantineStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, d := range s.dirs {
		if err := accounts.ImportQuarantineTx(ctx, tx, d.path, d.id, s.found); err != nil {
			return &StepError{UserID: d.id, Record: d.path, Err: err}
		}
	}
	return nil
}

func (s *quarantineStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	got, err := accounts.QuarantineTx(ctx, tx)
	if err != nil {
		return err
	}
	floor, err := accounts.IDFloorTx(ctx, tx)
	if err != nil {
		return err
	}
	for _, d := range s.dirs {
		if got[d.path] != d.id || floor < d.id {
			return &StepError{UserID: d.id, Record: d.path, Err: errors.New("legacy: the quarantine index differs")}
		}
	}
	if len(got) != len(s.dirs) {
		return errors.New("legacy: the quarantine index has extra entries")
	}
	return nil
}

func (s *quarantineStep) Report() StepReport {
	r := StepReport{Entity: "E33", Version: 1, Read: len(s.dirs), Written: len(s.dirs)}
	for _, d := range s.dirs {
		r.KeptInPlace = append(r.KeptInPlace, KeptPath{Path: d.path, Reason: "deleted_account"})
	}
	for _, p := range s.other {
		r.KeptInPlace = append(r.KeptInPlace, KeptPath{Path: p, Reason: "unrecognised_entry"})
	}
	for _, p := range s.implausible {
		r.KeptInPlace = append(r.KeptInPlace, KeptPath{Path: p, Reason: "implausible_account_id"})
		r.Notes = append(r.Notes, fmt.Sprintf("%s: the id is above %d and does not raise the id floor", p, maxDirectoryID))
	}
	return r
}
