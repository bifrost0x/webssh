package accounts

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestProvisionAndRelease(t *testing.T) {
	t.Parallel()
	s, _ := newService(t, "cfg_admin")
	ctx := t.Context()
	if _, err := s.Create(ctx, CreateRequest{Username: "Alice", Password: "password1", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}
	var id int64
	write := func(fn func(tx *store.Tx) error) error { return s.DB.Write(ctx, fn) }
	for _, c := range []struct {
		name, manager string
		code          fault.Code
	}{
		{"alice", "github", fault.Conflict},
		{"ab", "github", fault.InvalidValue},
		{"bad-name", "github", fault.InvalidValue},
		{"a\x00b", "ldap", fault.InvalidValue},
	} {
		err := write(func(tx *store.Tx) error { _, err := s.ProvisionTx(ctx, tx, c.name, c.manager); return err })
		if !fault.Is(err, c.code) {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		}
	}
	if err := write(func(tx *store.Tx) error { _, err := s.ProvisionTx(ctx, tx, "octo", "local"); return err }); err == nil {
		t.Fatal("unknown manager accepted")
	}
	// A name ADMIN_USERS lists is fine: managed accounts are never promoted.
	if err := write(func(tx *store.Tx) error {
		var err error
		id, err = s.ProvisionTx(ctx, tx, "cfg_admin", "github")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	a, err := s.Get(ctx, id)
	if err != nil || a.IsAdmin || a.Managed != ManagedGitHub || a.Incarnation == "" {
		t.Fatalf("provisioned %+v %v", a, err)
	}
	creds := s.Credentials.(*fakeCredentials)
	if _, ok := creds.stored[id]; ok {
		t.Fatal("managed account got a local password")
	}
	var gen int64
	if err := write(func(tx *store.Tx) error {
		if err := s.ReleaseTx(ctx, tx, id, ""); err != nil {
			return err
		}
		var err error
		gen, err = s.RaiseGenerationTx(ctx, tx, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	a, _ = s.Get(ctx, id)
	if a.Managed != ManagedLocal || gen != 1 || a.AuthGeneration != 1 {
		t.Fatalf("released %+v gen %d", a, gen)
	}
	if err := write(func(tx *store.Tx) error { return s.ReleaseTx(ctx, tx, id, "hash:x") }); err != nil || creds.stored[id] != "hash:x" {
		t.Fatalf("release with password: %v %v", err, creds.stored)
	}
	if err := write(func(tx *store.Tx) error { return s.ReleaseTx(ctx, tx, 999, "") }); !fault.Is(err, fault.NotFound) {
		t.Fatalf("release of a missing account: %v", err)
	}
	if err := write(func(tx *store.Tx) error { _, err := s.RaiseGenerationTx(ctx, tx, 999); return err }); !fault.Is(err, fault.NotFound) {
		t.Fatalf("raise for a missing account: %v", err)
	}
	if err := s.DB.Read(ctx, func(tx *store.Tx) error { _, err := s.GetTx(context.Background(), tx, 999); return err }); !fault.Is(err, fault.NotFound) {
		t.Fatalf("GetTx: %v", err)
	}
}
