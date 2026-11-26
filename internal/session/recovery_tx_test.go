package session

import (
	"errors"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestEndRecoveryCommitsWithTheCallersTransaction(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	s, _, err := f.svc.Issue(t.Context(), IssueRequest{UserID: 2, PrimaryMethod: "password", Methods: []string{"password", MethodRecovery}, Assurance: MFA})
	if err != nil {
		t.Fatal(err)
	}
	errRollback := errors.New("rollback")
	err = f.svc.db.Write(t.Context(), func(tx *store.Tx) error {
		if err := f.svc.EndRecovery(t.Context(), tx, s.ID, "totp", false); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
	if got, _ := f.svc.Lookup(t.Context(), s.ID); !got.Recovery() {
		t.Fatal("a rolled back transaction ended the restriction")
	}
	err = f.svc.db.Write(t.Context(), func(tx *store.Tx) error {
		return f.svc.EndRecovery(t.Context(), tx, s.ID, "", true)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.svc.Lookup(t.Context(), s.ID)
	if got.Recovery() || got.Assurance != Basic || !slices.Equal(got.Methods, []string{"password"}) {
		t.Fatalf("after EndRecovery: %+v", got)
	}
	err = f.svc.db.Write(t.Context(), func(tx *store.Tx) error {
		return f.svc.EndRecovery(t.Context(), tx, "missing", "", false)
	})
	if fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("missing session: %v", err)
	}
	err = f.svc.db.Write(t.Context(), func(tx *store.Tx) error {
		return f.svc.EndRecovery(t.Context(), tx, s.ID, "not a method!", false)
	})
	if fault.CodeOf(err) != fault.InvalidRequest {
		t.Fatalf("invalid replacement: %v", err)
	}
}
