package legacy

import (
	"context"

	"github.com/bifrost0x/webssh/internal/store"
)

// singleUserStores is the step of entity E35, the stores of the
// single-user layout of very old releases (DATA_DIR/profiles.json, keys/,
// commands/). Python 3.3.x does not read them as user data, so nothing is
// imported: the step lists each path with its size, and the files stay
// where they are (KEEP-IN-PLACE). It is the reference for steps that only
// account for legacy data.
type singleUserStores struct {
	paths []SingleUserPath
}

// AddSingleUserStores registers the step of E35.
func AddSingleUserStores(r *Registry) error {
	return r.Add(GroupInventory, func() Step { return &singleUserStores{} })
}

func (*singleUserStores) Entity() string { return "E35" }

func (*singleUserStores) Version() int { return 1 }

func (s *singleUserStores) Read(_ context.Context, src *Source) error {
	paths, err := src.SingleUserPaths()
	s.paths = paths
	return err
}

func (*singleUserStores) Write(context.Context, *store.Tx, Sealer) error { return nil }

func (*singleUserStores) Verify(context.Context, *store.Tx, Opener) error { return nil }

func (s *singleUserStores) Report() StepReport {
	r := StepReport{Entity: "E35", Version: 1, Read: len(s.paths)}
	for _, p := range s.paths {
		r.KeptInPlace = append(r.KeptInPlace, KeptPath{Path: p.Path, Reason: "legacy_single_user_store", Files: p.Files, Bytes: p.Bytes})
	}
	return r
}
