package vault

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

func TestProbeSealed(t *testing.T) {
	t.Parallel()
	r := newRig(t, Limits{})
	probe := func(db *store.DB) (bool, error) {
		var found bool
		err := db.Read(t.Context(), func(tx *store.Tx) error {
			var err error
			found, err = ProbeSealed(t.Context(), tx, r.ring)
			return err
		})
		return found, err
	}
	if found, err := probe(r.db); found || err != nil {
		t.Fatalf("empty store: %v, %v", found, err)
	}
	r.upload(t, principaltest.User(1), "k", newEd25519PEM(t))
	if found, err := probe(r.db); !found || err != nil {
		t.Fatalf("with a key: %v, %v", found, err)
	}
	// Another ring does not open the key.
	err := r.db.Read(t.Context(), func(tx *store.Tx) error {
		_, err := ProbeSealed(t.Context(), tx, newRing(t))
		return err
	})
	if err == nil {
		t.Error("a foreign ring opened the key")
	}
	// A database without the vault table has nothing to probe.
	other := storetest.Open(t)
	if err := other.Read(t.Context(), func(tx *store.Tx) error {
		found, err := ProbeSealed(t.Context(), tx, r.ring)
		if found {
			t.Error("found a key without the table")
		}
		return err
	}); err != nil {
		t.Error(err)
	}
}
