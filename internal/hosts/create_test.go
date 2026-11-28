package hosts

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// The hook of a create sees the new record in its own transaction, and an
// error of the hook leaves nothing stored.
func TestCreateRunsTheHookInTheTransaction(t *testing.T) {
	s := seeded(t, Legacy{})
	ctx := t.Context()
	creates := map[string]func(Created) (jsontext.Value, error){
		"profile": func(then Created) (jsontext.Value, error) {
			return s.CreateProfile(ctx, 9, newHost("Hooked"), then)
		},
		"jump": func(then Created) (jsontext.Value, error) {
			return s.CreateJumpHost(ctx, 9, protocol.HostsJumpSave{Name: v(`"J"`), Host: v(`"j.example"`),
				Username: v(`"u"`), AuthType: v(`"password"`)}, then)
		},
		"socks": func(then Created) (jsontext.Value, error) {
			return s.CreateSOCKSProxy(ctx, 9, protocol.HostsSOCKSSave{Name: v(`"S"`), Host: v(`"s.example"`),
				Username: v(`"u"`), AuthType: v(`"password"`)}, then)
		},
	}
	count := func() int {
		var n int
		if err := s.DB.Read(ctx, func(tx *store.Tx) error {
			l, err := Export(ctx, tx, 9)
			n = len(l.Profiles) + len(l.JumpHosts) + len(l.SOCKSProxies)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	refused := errors.New("assignment failed")
	for name, create := range creates {
		if _, err := create(func(context.Context, *store.Tx, jsontext.Value) error { return refused }); !errors.Is(err, refused) {
			t.Fatalf("%s: %v, want the hook's error", name, err)
		}
		if n := count(); n != 0 {
			t.Fatalf("%s: %d records stored although the hook failed", name, n)
		}
	}
	for name, create := range creates {
		seen := 0
		saved, err := create(func(ctx context.Context, tx *store.Tx, rec jsontext.Value) error {
			l, err := Export(ctx, tx, 9)
			seen = len(l.Profiles) + len(l.JumpHosts) + len(l.SOCKSProxies)
			return err
		})
		if err != nil || len(saved) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		if seen != count() {
			t.Errorf("%s: the hook saw %d records, %d are stored", name, seen, count())
		}
	}
}

func TestCreateRefusesAnUpdate(t *testing.T) {
	s := seeded(t, Legacy{})
	req := newHost("Other")
	req.ID = v(`"c11ae780-b6eb-4dac-a794-d27d0b23f255"`)
	if _, err := s.CreateProfile(t.Context(), oracleUser, req, nil); code(err) != fault.ValidationError {
		t.Errorf("profile update through create: %v", err)
	}
	if _, err := s.CreateJumpHost(t.Context(), oracleUser, protocol.HostsJumpSave{JumpHostID: v(`"x"`)}, nil); code(err) != fault.ValidationError {
		t.Errorf("jump host update through create: %v", err)
	}
	if _, err := s.CreateSOCKSProxy(t.Context(), oracleUser, protocol.HostsSOCKSSave{SOCKSProxyID: v(`"x"`)}, nil); code(err) != fault.ValidationError {
		t.Errorf("SOCKS proxy update through create: %v", err)
	}
}
