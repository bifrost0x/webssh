package totp

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestProbeSealed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	probe := func(ring *keyring.Ring) (bool, error) {
		var found bool
		err := e.svc.DB.Read(t.Context(), func(tx *store.Tx) error {
			var err error
			found, err = ProbeSealed(t.Context(), tx, ring)
			return err
		})
		return found, err
	}
	if found, err := probe(e.svc.Ring); found || err != nil {
		t.Fatalf("no authenticator: %v, %v", found, err)
	}
	e.enrol(t, principaltest.User(3))
	if found, err := probe(e.svc.Ring); !found || err != nil {
		t.Fatalf("with an authenticator: %v, %v", found, err)
	}
	other, err := keyring.Open([]byte("other-secret"), make([]byte, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe(other); err == nil {
		t.Error("a foreign ring opened the secret")
	}
}
