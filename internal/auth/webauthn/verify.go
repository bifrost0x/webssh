package webauthn

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
)

// RelyingParty is the WebAuthn configuration: WEBAUTHN_RP_ID,
// WEBAUTHN_RP_NAME and WEBAUTHN_ORIGIN, used exactly as configured. The
// RP ID hash and the origin comparison of every migrated passkey depend
// on these values (invariant I-02).
type RelyingParty struct {
	ID     string
	Name   string
	Origin string
}

var (
	errCredential = errors.New("webauthn: malformed credential")
	errRPID       = errors.New("webauthn: RP ID hash does not match")
	errUser       = errors.New("webauthn: user presence or verification missing")
	errCounter    = errors.New("webauthn: signature counter did not increase")
	errBackup     = errors.New("webauthn: backup eligibility changed")
	errHandle     = errors.New("webauthn: user handle does not match")
)

const (
	maxTransports     = 8
	maxTransportBytes = 32
)

type credentialJSON struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string         `json:"clientDataJSON"`
		AttestationObject string         `json:"attestationObject"`
		Transports        jsontext.Value `json:"transports"`
		AuthenticatorData string         `json:"authenticatorData"`
		Signature         string         `json:"signature"`
		UserHandle        *string        `json:"userHandle"`
	} `json:"response"`
}

// parseCredential decodes the PublicKeyCredential JSON of webauthn.js and
// returns it with its raw credential ID: id must be the base64url form of
// rawId and type "public-key".
func parseCredential(raw jsontext.Value) (credentialJSON, []byte, error) {
	var c credentialJSON
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, nil, fmt.Errorf("%w: %w", errCredential, err)
	}
	id, err := decodeB64URL(c.RawID)
	if err != nil || len(id) == 0 || len(id) > MaxCredentialIDBytes || encodeB64URL(id) != c.ID {
		return c, nil, fmt.Errorf("%w: id and rawId differ", errCredential)
	}
	if c.Type != "public-key" {
		return c, nil, fmt.Errorf("%w: type %q", errCredential, c.Type)
	}
	return c, id, nil
}

// Registration is a verified new credential.
type Registration struct {
	CredentialID []byte
	COSEKey      []byte
	Alg          int64
	SignCount    uint32
	Flags        byte
	Format       string
	Transports   []string
}

// VerifyRegistration checks a navigator.credentials.create() response
// against the expected challenge (Level 3, section 7.1). User presence and
// user verification are required.
func (rp RelyingParty) VerifyRegistration(credential jsontext.Value, challenge []byte) (Registration, error) {
	return rp.verifyRegistration(credential, challenge, true)
}

func (rp RelyingParty) verifyRegistration(credential jsontext.Value, challenge []byte, requireUV bool) (Registration, error) {
	c, id, err := parseCredential(credential)
	if err != nil {
		return Registration{}, err
	}
	cdj, err1 := decodeB64URL(c.Response.ClientDataJSON)
	attObj, err2 := decodeB64URL(c.Response.AttestationObject)
	if err := errors.Join(err1, err2); err != nil {
		return Registration{}, fmt.Errorf("%w: %w", errCredential, err)
	}
	if err := checkClientData(cdj, typeCreate, challenge, rp.Origin); err != nil {
		return Registration{}, err
	}
	att, err := parseAttestationObject(attObj)
	if err != nil {
		return Registration{}, err
	}
	ad, err := parseAuthData(att.AuthData)
	if err != nil {
		return Registration{}, err
	}
	if err := rp.checkFlags(ad, requireUV); err != nil {
		return Registration{}, err
	}
	if !ad.Has(FlagAT) {
		return Registration{}, fmt.Errorf("%w: no attested credential data", errAuthData)
	}
	if !bytes.Equal(ad.CredentialID, id) {
		return Registration{}, fmt.Errorf("%w: credential ID differs from rawId", errCredential)
	}
	if err := verifyStatement(att, ad, sha256.Sum256(cdj)); err != nil {
		return Registration{}, err
	}
	return Registration{
		CredentialID: bytes.Clone(id), COSEKey: bytes.Clone(ad.COSEKey), Alg: ad.Key.Alg,
		SignCount: ad.SignCount, Flags: ad.Flags, Format: att.Format, Transports: transports(c.Response.Transports),
	}, nil
}

func (rp RelyingParty) checkFlags(ad AuthData, requireUV bool) error {
	want := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(ad.RPIDHash[:], want[:]) != 1 {
		return errRPID
	}
	if !ad.Has(FlagUP) || requireUV && !ad.Has(FlagUV) {
		return errUser
	}
	return nil
}

// transports keeps the string entries of the transports list, bounded;
// they are informational only.
func transports(raw jsontext.Value) []string {
	var all []jsontext.Value
	if len(raw) == 0 || json.Unmarshal(raw, &all) != nil {
		return []string{}
	}
	out := []string{}
	for _, v := range all {
		var s string
		if json.Unmarshal(v, &s) == nil && s != "" && len(s) <= maxTransportBytes && len(out) < maxTransports {
			out = append(out, s)
		}
	}
	return out
}

// Assertion is a parsed navigator.credentials.get() response.
type Assertion struct {
	CredentialID []byte
	// UserHandle is nil when the authenticator returned none.
	UserHandle []byte

	clientData []byte
	authData   []byte
	signature  []byte
}

// ParseAssertion decodes an assertion; it is verified with Verify once the
// stored credential is known.
func ParseAssertion(credential jsontext.Value) (Assertion, error) {
	c, id, err := parseCredential(credential)
	if err != nil {
		return Assertion{}, err
	}
	a := Assertion{CredentialID: id}
	var e1, e2, e3, e4 error
	a.clientData, e1 = decodeB64URL(c.Response.ClientDataJSON)
	a.authData, e2 = decodeB64URL(c.Response.AuthenticatorData)
	a.signature, e3 = decodeB64URL(c.Response.Signature)
	if h := c.Response.UserHandle; h != nil && *h != "" {
		a.UserHandle, e4 = decodeB64URL(*h)
	}
	if err := errors.Join(e1, e2, e3, e4); err != nil {
		return Assertion{}, fmt.Errorf("%w: %w", errCredential, err)
	}
	return a, nil
}

// Stored is what the server knows about a credential.
type Stored struct {
	Key       PublicKey
	SignCount uint32
	// UserHandle is the handle the credential was registered with: the
	// owner's id in ASCII decimal.
	UserHandle string
	// BackupEligible is the BE flag seen at registration; nil for
	// credentials migrated from the Python release, which did not keep it.
	BackupEligible *bool
}

// Expect are the conditions of one assertion ceremony.
type Expect struct {
	Challenge []byte
	// HandleRequired is set for a sign-in without a user name: the user
	// handle is the only link to the account (section 7.2 step 6).
	HandleRequired bool
}

// Verified is the outcome of an assertion.
type Verified struct {
	SignCount uint32
	Flags     byte
}

// Verify checks the assertion against a stored credential (Level 3,
// section 7.2): client data, RP ID hash, user presence and verification,
// backup flags, user handle, the signature and the counter rule of the
// Python release: once either counter is non-zero, the new one must be
// greater than the stored one.
func (rp RelyingParty) Verify(a Assertion, s Stored, e Expect) (Verified, error) {
	return rp.verify(a, s, e, true)
}

func (rp RelyingParty) verify(a Assertion, s Stored, e Expect, requireUV bool) (Verified, error) {
	if err := checkClientData(a.clientData, typeGet, e.Challenge, rp.Origin); err != nil {
		return Verified{}, err
	}
	ad, err := parseAuthData(a.authData)
	if err != nil {
		return Verified{}, err
	}
	if err := rp.checkFlags(ad, requireUV); err != nil {
		return Verified{}, err
	}
	if s.BackupEligible != nil && *s.BackupEligible != ad.Has(FlagBE) {
		return Verified{}, errBackup
	}
	if a.UserHandle == nil && e.HandleRequired ||
		a.UserHandle != nil && subtle.ConstantTimeCompare(a.UserHandle, []byte(s.UserHandle)) != 1 {
		return Verified{}, errHandle
	}
	cdHash := sha256.Sum256(a.clientData)
	signed := make([]byte, 0, len(a.authData)+len(cdHash))
	signed = append(append(signed, a.authData...), cdHash[:]...)
	if err := s.Key.Verify(signed, a.signature); err != nil {
		return Verified{}, err
	}
	if (ad.SignCount > 0 || s.SignCount > 0) && ad.SignCount <= s.SignCount {
		return Verified{}, errCounter
	}
	return Verified{SignCount: ad.SignCount, Flags: ad.Flags}, nil
}
