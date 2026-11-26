package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Authenticator data flags (WebAuthn Level 3, section 6.1).
const (
	FlagUP = 0x01 // user present
	FlagUV = 0x04 // user verified
	FlagBE = 0x08 // backup eligible
	FlagBS = 0x10 // backed up
	FlagAT = 0x40 // attested credential data included
	FlagED = 0x80 // extension data included
)

// MaxCredentialIDBytes is the longest credential ID the specification
// allows (Level 3, section 7.1, step 21 of the registration).
const MaxCredentialIDBytes = 1023

const authDataMinBytes = 37 // rpIdHash, flags, signCount

var errAuthData = errors.New("webauthn: invalid authenticator data")

// AuthData is parsed authenticator data. Credential fields are set when
// FlagAT is.
type AuthData struct {
	RPIDHash     [32]byte
	Flags        byte
	SignCount    uint32
	AAGUID       [16]byte
	CredentialID []byte
	// COSEKey is the credential public key as encoded by the authenticator.
	COSEKey []byte
	Key     PublicKey
}

// Has reports whether every flag of mask is set.
func (a AuthData) Has(mask byte) bool { return a.Flags&mask == mask }

// parseAuthData parses authenticator data strictly: the attested
// credential data and the extension map must be present exactly when
// their flags say so, both must be well-formed, and nothing may follow.
// A credential that is backed up but not backup eligible is invalid.
func parseAuthData(b []byte) (AuthData, error) {
	var a AuthData
	if len(b) < authDataMinBytes {
		return a, fmt.Errorf("%w: %d bytes", errAuthData, len(b))
	}
	copy(a.RPIDHash[:], b[:32])
	a.Flags = b[32]
	a.SignCount = binary.BigEndian.Uint32(b[33:37])
	if a.Has(FlagBS) && !a.Has(FlagBE) {
		return a, fmt.Errorf("%w: backed up but not backup eligible", errAuthData)
	}
	rest := b[authDataMinBytes:]
	if a.Has(FlagAT) {
		if len(rest) < 18 {
			return a, fmt.Errorf("%w: truncated attested credential data", errAuthData)
		}
		copy(a.AAGUID[:], rest[:16])
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > MaxCredentialIDBytes || n > len(rest) {
			return a, fmt.Errorf("%w: credential ID of %d bytes", errAuthData, n)
		}
		a.CredentialID = rest[:n:n]
		rest = rest[n:]
		v, used, err := decodeCBORPrefix(rest)
		if err != nil {
			return a, fmt.Errorf("%w: credential public key: %w", errAuthData, err)
		}
		if a.Key, err = coseKeyFrom(v); err != nil {
			return a, err
		}
		a.COSEKey = rest[:used:used]
		rest = rest[used:]
	}
	if a.Has(FlagED) {
		v, used, err := decodeCBORPrefix(rest)
		if err != nil {
			return a, fmt.Errorf("%w: extensions: %w", errAuthData, err)
		}
		if _, ok := v.(cborMap); !ok {
			return a, fmt.Errorf("%w: extensions are not a map", errAuthData)
		}
		rest = rest[used:]
	}
	if len(rest) != 0 {
		return a, fmt.Errorf("%w: %d trailing bytes", errAuthData, len(rest))
	}
	return a, nil
}
