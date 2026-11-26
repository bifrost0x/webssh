package accounts

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestMFARequiredTxReadsTheFlagInTheTransaction(t *testing.T) {
	t.Parallel()
	s, _ := newService(t)
	a, err := s.Create(t.Context(), CreateRequest{Username: "admin", Password: "password1", FirstOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	err = s.DB.Write(t.Context(), func(tx *store.Tx) error {
		before, err := s.MFARequiredTx(t.Context(), tx, a.ID)
		if err != nil || before {
			t.Fatalf("before = %v, %v", before, err)
		}
		if err := s.SetMFARequiredTx(t.Context(), tx, a.ID, true); err != nil {
			return err
		}
		after, err := s.MFARequiredTx(t.Context(), tx, a.ID)
		if err != nil || !after {
			t.Fatalf("after = %v, %v", after, err)
		}
		_, err = s.MFARequiredTx(t.Context(), tx, a.ID+100)
		if fault.CodeOf(err) != fault.NotFound {
			t.Fatalf("missing account: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
