package vault

import (
	"bytes"
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

// Migrated keys keep ID, name, type, upload time and order; the public key
// equals the Python release's; keys Go cannot load stay listed as unusable
// and can be replaced.
func TestImportKey(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	stored, _ := goldenKeys(t)
	protected := goldenByLabel(t, "ed25519-openssh-passphrase")
	ctx := context.Background()
	type entry struct {
		id  string
		key goldenKey
	}
	var entries []entry
	for i, k := range append([]goldenKey{protected}, stored...) {
		entries = append(entries, entry{id: "legacy-" + string(rune('a'+i)), key: k})
	}
	if err := r.db.Write(ctx, func(tx *store.Tx) error {
		for _, e := range entries {
			keyType := e.key.KeyType
			if keyType == "" {
				keyType = e.key.Algorithm
			}
			pub, err := ImportKey(ctx, tx, r.ring, Imported{
				ID: e.id, UserID: alice.UserID, Name: "名前 " + e.key.Label, KeyType: keyType,
				UploadedAt: "2025-01-02T03:04:05.123456", PEM: e.key.pem(t),
			})
			if err != nil {
				return err
			}
			if want := e.key.Public; !e.key.Protected && pub != want {
				t.Errorf("%s: public key %q, Python %q", e.key.Label, pub, want)
			}
			if e.key.Protected && pub != "" {
				t.Errorf("%s: unsupported key with public key", e.key.Label)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	list, err := r.svc.List(as(alice))
	if err != nil || len(list) != len(entries) {
		t.Fatalf("list %d %v", len(list), err)
	}
	for i, s := range list {
		e := entries[i]
		if s.ID != e.id || s.Name != "名前 "+e.key.Label || s.UploadedAt != "2025-01-02T03:04:05.123456" || s.Usable == e.key.Protected {
			t.Errorf("%d: %+v", i, s)
		}
	}
	if _, err := r.svc.Signer(ctx, alice.UserID, entries[0].id); err == nil {
		t.Fatal("unsupported key gave a signer")
	}
	// The unsupported key is replaced by a loadable one of the same type.
	got, err := r.svc.Replace(as(alice), Replace{ID: entries[0].id, Content: string(newEd25519PEM(t)), Grant: r.grant(alice, "key.replace", entries[0].id)})
	if err != nil || !got.Usable {
		t.Fatalf("replace unsupported: %+v %v", got, err)
	}
	// The sealed value of a migrated key is the file as it was.
	if err := r.db.Read(ctx, func(tx *store.Tx) error {
		row, _, err := getRow(ctx, tx, alice.UserID, entries[1].id)
		if err != nil {
			return err
		}
		plain, err := r.ring.Open("ssh_key", aad(alice.UserID, row.ID), row.Sealed)
		if err != nil {
			return err
		}
		if !bytes.Equal(plain, entries[1].key.pem(t)) {
			t.Error("migrated key not sealed verbatim")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestImportRefusesInvalidUser(t *testing.T) {
	r := newRig(t, Limits{})
	err := r.db.Write(context.Background(), func(tx *store.Tx) error {
		_, err := ImportKey(context.Background(), tx, r.ring, Imported{ID: "x", PEM: newEd25519PEM(t)})
		return err
	})
	if err == nil {
		t.Fatal("import without user accepted")
	}
}
