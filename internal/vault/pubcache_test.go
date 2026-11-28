package vault

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

type countingSealer struct {
	Sealer
	opens atomic.Int32
}

func (c *countingSealer) Open(p keyring.Purpose, ad keyring.AAD, sealed []byte) ([]byte, error) {
	c.opens.Add(1)
	return c.Sealer.Open(p, ad, sealed)
}

// Approval checks of automation runs ask for the public key of the same
// stored key many times; opening the sealed key each time costs an AEAD
// open and a private-key parse, a full RSA operation for RSA keys. The
// key is opened once per sealed value: the answer equals the signer's
// public key, another owner still gets not found, and a new sealed value
// (another key, a rotation) is opened again.
func TestPublicKeyOpensEachSealedKeyOnce(t *testing.T) {
	r := newRig(t, Limits{})
	counter := &countingSealer{Sealer: r.ring}
	r.svc.sealer = counter
	alice, bob := principaltest.User(1), principaltest.User(2)
	s := r.upload(t, alice, "k", newEd25519PEM(t))
	ctx := context.Background()
	signer, err := r.svc.Signer(ctx, alice.UserID, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := signer.PublicKey().Marshal()
	counter.opens.Store(0)
	for range 50 {
		got, err := r.svc.PublicKey(ctx, alice.UserID, s.ID)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("PublicKey = %x, %v; want %x", got, err, want)
		}
		got[0] ^= 0xff // callers may not change the cached value
	}
	if n := counter.opens.Load(); n != 1 {
		t.Fatalf("50 lookups opened the sealed key %d times, want 1", n)
	}
	if _, err := r.svc.PublicKey(ctx, bob.UserID, s.ID); fault.CodeOf(err) != fault.NotFound {
		t.Fatalf("other owner: %v", err)
	}

	// Replace the sealed value in place, as a rotation does: the cached
	// answer must not survive it.
	other := r.upload(t, alice, "other", newEd25519PEM(t))
	otherSigner, err := r.svc.Signer(ctx, alice.UserID, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := r.ring.Open(keyring.SSHKey, aad(alice.UserID, other.ID), sealedOf(t, r, alice, other.ID))
	if err != nil {
		t.Fatal(err)
	}
	resealed, err := r.ring.Seal(keyring.SSHKey, aad(alice.UserID, s.ID), plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE vault_ssh_keys SET private_key = ? WHERE user_id = ? AND id = ?`, resealed, alice.UserID, s.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := r.svc.PublicKey(ctx, alice.UserID, s.ID)
	if err != nil || !bytes.Equal(got, otherSigner.PublicKey().Marshal()) {
		t.Fatalf("after the sealed value changed: %x, %v", got, err)
	}
}

func sealedOf(t *testing.T, r *rig, p principal.Principal, id string) []byte {
	t.Helper()
	var sealed []byte
	if err := r.db.Read(context.Background(), func(tx *store.Tx) error {
		row, _, err := getRow(context.Background(), tx, p.UserID, id)
		sealed = row.Sealed
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return sealed
}
