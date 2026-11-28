package smb

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// A share created with a hook is stored together with what the hook
// writes, or not at all.
func TestShareCreateRunsTheHookInTheTransaction(t *testing.T) {
	s := &Shares{DB: storetest.Open(t, Schema())}
	ctx := t.Context()
	req := SaveRequest{Name: jsontext.Value(`"NAS"`), Host: jsontext.Value(`"nas.example"`),
		Share: jsontext.Value(`"Data"`), Username: jsontext.Value(`"u"`)}
	refused := errors.New("assignment failed")
	if _, err := s.Create(ctx, 1, req, func(context.Context, *store.Tx, jsontext.Value) error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("%v, want the hook's error", err)
	}
	if list, err := s.List(ctx, 1); err != nil || len(list) != 0 {
		t.Fatalf("stored after a failed hook: %v %v", list, err)
	}
	seen := 0
	saved, err := s.Create(ctx, 1, req, func(ctx context.Context, tx *store.Tx, _ jsontext.Value) error {
		recs, err := SharesTx(ctx, tx, 1)
		seen = len(recs)
		return err
	})
	if err != nil || len(saved) == 0 || seen != 1 {
		t.Fatalf("create: %s %v, the hook saw %d", saved, err, seen)
	}
}
