package keyring

import (
	"bytes"
	"errors"
	"testing"
)

func TestRotation(t *testing.T) {
	t.Parallel()
	from := katRing(t)
	to, err := Open([]byte("the-new-secret-key"), katMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRotation(from, to, false); !errors.Is(err, ErrRotationLegacy) {
		t.Fatalf("rotation before the purge: %v", err)
	}
	otherMaterial, err := Open([]byte("the-new-secret-key"), seq(0x40, 0x5f))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRotation(from, otherMaterial, true); !errors.Is(err, ErrRotationMaterial) {
		t.Fatalf("rotation with new material: %v", err)
	}
	if _, err := NewRotation(from, katRing(t), true); !errors.Is(err, ErrRotationSameKey) {
		t.Fatalf("rotation to the same key: %v", err)
	}
	rt, err := NewRotation(from, to, true)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := from.Seal(TOTP, katAAD, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	resealed, err := rt.Reseal(TOTP, katAAD, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := from.Open(TOTP, katAAD, resealed); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("old key opens the resealed value: %v", err)
	}
	plain, err := to.Open(TOTP, katAAD, resealed)
	if err != nil || string(plain) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("new key: %q, %v", plain, err)
	}
	if _, err := rt.Reseal(TOTP, AAD{"x", "y", "z"}, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("reseal for another record: %v", err)
	}
	if h := rt.OldHeader(); !bytes.Equal(h, sealed[:headerSize]) || bytes.Equal(h, resealed[:headerSize]) {
		t.Fatalf("old header %x: sealed %x, resealed %x", h, sealed[:headerSize], resealed[:headerSize])
	}
	if rt.To() != to {
		t.Fatal("To is not the new ring")
	}
}

// A restored database is resealed from the archive's ring to the
// installation's, whatever material either has.
func TestRestoreRotation(t *testing.T) {
	t.Parallel()
	archive := katRing(t)
	if _, err := NewRestoreRotation(archive, katRing(t)); !errors.Is(err, ErrRotationSameKey) {
		t.Fatalf("reseal to the same key: %v", err)
	}
	installation, err := Open([]byte("the-installation-secret"), seq(0x40, 0x5f))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRestoreRotation(archive, installation)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := archive.Seal(TOTP, katAAD, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	resealed, err := rt.Reseal(TOTP, katAAD, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := installation.Open(TOTP, katAAD, resealed); err != nil || string(plain) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("resealed value: %q %v", plain, err)
	}
	if _, err := archive.Open(TOTP, katAAD, resealed); err == nil {
		t.Fatal("the archive's ring opens the resealed value")
	}
	if !bytes.HasPrefix(sealed, rt.OldHeader()) || bytes.HasPrefix(resealed, rt.OldHeader()) {
		t.Fatal("old header")
	}
}
