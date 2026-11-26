package legacy

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/store"
)

// recoveryCodesStep migrates entity E11: the remaining recovery code
// hashes (SHA-256 with the domain prefix) of every account, unchanged.
// Consumed codes are already deleted in Python.
type recoveryCodesStep struct {
	hashes map[int64][][]byte
}

func (*recoveryCodesStep) Entity() string { return "E11" }

func (*recoveryCodesStep) Version() int { return 1 }

func (s *recoveryCodesStep) Read(ctx context.Context, src *Source) error {
	var err error
	s.hashes, err = src.RecoveryCodeHashes(ctx)
	return err
}

func (s *recoveryCodesStep) users() []int64 { return slices.Sorted(maps.Keys(s.hashes)) }

func (s *recoveryCodesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	rc := &auth.Recovery{}
	for _, id := range s.users() {
		if err := rc.ImportTx(ctx, tx, id, s.hashes[id]); err != nil {
			return &StepError{UserID: id, Err: err}
		}
	}
	return nil
}

func (s *recoveryCodesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, id := range s.users() {
		got, err := auth.RecoveryHashesTx(ctx, tx, id)
		if err != nil || !slices.EqualFunc(got, s.hashes[id], bytes.Equal) {
			return &StepError{UserID: id, Err: errors.Join(errors.New("legacy: the stored recovery codes differ"), err)}
		}
	}
	return nil
}

func (s *recoveryCodesStep) Report() StepReport {
	n := 0
	for _, h := range s.hashes {
		n += len(h)
	}
	return StepReport{Entity: "E11", Version: 1, Read: n, Written: n}
}
