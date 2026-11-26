package oidc

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

func TestLinksRules(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	l := &Links{DB: storetest.Open(t, Schema())}
	id := auth.Identity{Issuer: "https://idp.example", Subject: "s"}
	if _, err := l.Account(ctx, id); !fault.Is(err, fault.NotFound) {
		t.Fatalf("unlinked: %v", err)
	}
	if _, err := l.Provision(ctx, id); !fault.Is(err, fault.Forbidden) {
		t.Fatalf("OIDC provisioned: %v", err)
	}
	a, err := l.Link(ctx, 1, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []int64{1, 2} {
		if _, err := l.Link(ctx, user, id); !fault.Is(err, fault.Conflict) {
			t.Fatalf("second link to %d: %v", user, err)
		}
	}
	// Found by issuer and subject only; another issuer is another identity.
	if _, err := l.Account(ctx, auth.Identity{Issuer: "https://other.example", Subject: "s"}); !fault.Is(err, fault.NotFound) {
		t.Fatal("matched across issuers")
	}
	if _, err := l.Link(ctx, 1, auth.Identity{Issuer: "https://idp.example", Subject: "s2"}); err != nil {
		t.Fatalf("second identity of an account: %v", err)
	}
	if list, err := l.List(ctx, 1); err != nil || len(list) != 2 || list[0].ID != a.ID {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := l.Unlink(ctx, 2, a.ID); !fault.Is(err, fault.NotFound) {
		t.Fatalf("unlink of another account's identity: %v", err)
	}
	if err := l.Unlink(ctx, 1, a.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := l.HasIdentity(ctx, 2); err != nil || ok {
		t.Fatalf("has identity: %v %v", ok, err)
	}
}

func TestImportKeepsRows(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.Open(t, Schema())
	created := time.Date(2025, 3, 1, 8, 0, 0, 123456000, time.UTC)
	rows := []Imported{{ID: 7, UserID: 3, Issuer: "https://idp.example", Subject: "ü-subject", CreatedAt: created}}
	err := db.Write(ctx, func(tx *store.Tx) error {
		if err := ImportTx(ctx, tx, rows[0]); err != nil {
			return err
		}
		dup := rows[0]
		dup.ID = 8
		if ImportTx(ctx, tx, dup) == nil {
			t.Error("duplicate issuer and subject imported")
		}
		got, err := ImportedTx(ctx, tx)
		if err != nil || len(got) != 1 || got[0] != rows[0] {
			t.Errorf("read back %+v %v", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := (&Links{DB: db}).Account(ctx, auth.Identity{Issuer: "https://idp.example", Subject: "ü-subject"}); err != nil || id != 3 {
		t.Fatalf("imported identity resolves to %d: %v", id, err)
	}
	if isoformat(created) != "2025-03-01T08:00:00.123456" || isoformat(created.Truncate(time.Second)) != "2025-03-01T08:00:00" {
		t.Fatal("isoformat")
	}
}
