package keyring

import (
	"crypto/subtle"
	"errors"
)

// Errors of NewRotation.
var (
	// ErrRotationLegacy refuses a rotation while legacy data may still be
	// needed: the legacy data is encrypted with the current SECRET_KEY
	// (migration specification, section 4.9).
	ErrRotationLegacy = errors.New("keyring: SECRET_KEY cannot be rotated while legacy data exists; " +
		"confirm that the way back is no longer needed, run `webssh legacy purge`, then rotate")
	// ErrRotationMaterial refuses rings with different material: rotation
	// keeps the material and changes only SECRET_KEY.
	ErrRotationMaterial = errors.New("keyring: rotation must keep the keyring material")
	// ErrRotationSameKey refuses a rotation to the key already in use.
	ErrRotationSameKey = errors.New("keyring: the new SECRET_KEY yields the current key")
)

// Rotation reseals records from the current ring to the ring of a new
// SECRET_KEY with the same material. The caller reseals every keyring
// record in one database transaction and stores the new key identifier in
// the same transaction; MACs of tokens cannot be converted and their
// records are revoked instead.
type Rotation struct {
	from, to *Ring
}

// NewRotation prepares a rotation. legacyPurged is true only when the
// database holds the entry of a completed `webssh legacy purge` (state S4,
// or S5 after the purge recorded its entry).
func NewRotation(from, to *Ring, legacyPurged bool) (*Rotation, error) {
	if !legacyPurged {
		return nil, ErrRotationLegacy
	}
	if subtle.ConstantTimeCompare(from.material[:], to.material[:]) != 1 {
		return nil, ErrRotationMaterial
	}
	if from.id == to.id {
		return nil, ErrRotationSameKey
	}
	return &Rotation{from: from, to: to}, nil
}

// ErrRotationVerify reports a resealed value that does not open to the
// original plaintext under the new ring.
var ErrRotationVerify = errors.New("keyring: a resealed value does not verify under the new SECRET_KEY")

// Reseal opens a value with the current ring and seals it for the same
// record with the new one. The new value is opened again and compared
// with the plaintext before it is returned.
func (rt *Rotation) Reseal(p Purpose, ad AAD, sealed []byte) ([]byte, error) {
	plain, err := rt.from.Open(p, ad, sealed)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	out, err := rt.to.Seal(p, ad, plain)
	if err != nil {
		return nil, err
	}
	back, err := rt.to.Open(p, ad, out)
	if err != nil || subtle.ConstantTimeCompare(back, plain) != 1 {
		return nil, ErrRotationVerify
	}
	clear(back)
	return out, nil
}

// OldHeader is the prefix every value sealed by the current ring starts
// with (format version and key identifier). After a rotation no stored
// value may start with it.
func (rt *Rotation) OldHeader() []byte {
	return append([]byte{sealVersion}, rt.from.id[:]...)
}

// To is the ring of the new SECRET_KEY.
func (rt *Rotation) To() *Ring { return rt.to }
