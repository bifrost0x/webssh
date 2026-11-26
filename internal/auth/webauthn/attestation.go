package webauthn

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Attestation statement formats WebSSH verifies. The registration options
// ask for attestation "none", so browsers send "none"; a client that passes
// the authenticator's self attestation through sends "packed". Attestation
// is never used for trust decisions (the Python release had no trust
// anchors either), but a statement that is sent must be valid.
const (
	FormatNone   = "none"
	FormatPacked = "packed"
)

var (
	errAttestation = errors.New("webauthn: invalid attestation")
	// oidAAGUID is id-fido-gen-ce-aaguid (WebAuthn Level 3, section 8.2.1).
	oidAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
)

// attestationObject is a parsed attestationObject.
type attestationObject struct {
	Format   string
	Stmt     cborMap
	AuthData []byte
}

func parseAttestationObject(raw []byte) (attestationObject, error) {
	v, err := decodeCBOR(raw)
	if err != nil {
		return attestationObject{}, fmt.Errorf("%w: %w", errAttestation, err)
	}
	m, ok := v.(cborMap)
	if !ok {
		return attestationObject{}, fmt.Errorf("%w: not a map", errAttestation)
	}
	var a attestationObject
	var okFmt, okStmt, okData bool
	a.Format, okFmt = m["fmt"].(string)
	a.Stmt, okStmt = m["attStmt"].(cborMap)
	a.AuthData, okData = m["authData"].([]byte)
	if !okFmt || !okStmt || !okData {
		return attestationObject{}, fmt.Errorf("%w: missing fmt, attStmt or authData", errAttestation)
	}
	return a, nil
}

// verifyStatement checks the attestation statement of a registration
// (section 8.2 packed, section 8.7 none) against the parsed authenticator
// data and the hash of clientDataJSON.
func verifyStatement(a attestationObject, ad AuthData, clientDataHash [32]byte) error {
	switch a.Format {
	case FormatNone:
		if len(a.Stmt) != 0 {
			return fmt.Errorf("%w: none attestation with a statement", errAttestation)
		}
		return nil
	case FormatPacked:
		return verifyPacked(a, ad, clientDataHash)
	}
	return fmt.Errorf("%w: unsupported format %q", errAttestation, a.Format)
}

func verifyPacked(a attestationObject, ad AuthData, clientDataHash [32]byte) error {
	alg, okAlg := a.Stmt["alg"].(int64)
	sig, okSig := a.Stmt["sig"].([]byte)
	if !okAlg || !okSig || len(sig) == 0 {
		return fmt.Errorf("%w: packed statement without alg or sig", errAttestation)
	}
	if _, ok := a.Stmt["ecdaaKeyId"]; ok {
		return fmt.Errorf("%w: ECDAA is not supported", errAttestation)
	}
	signed := make([]byte, 0, len(a.AuthData)+len(clientDataHash))
	signed = append(append(signed, a.AuthData...), clientDataHash[:]...)
	rawChain, hasChain := a.Stmt["x5c"]
	if !hasChain {
		// Self attestation: signed with the credential key itself.
		if alg != ad.Key.Alg {
			return fmt.Errorf("%w: self attestation alg %d, credential alg %d", errAttestation, alg, ad.Key.Alg)
		}
		if err := ad.Key.Verify(signed, sig); err != nil {
			return fmt.Errorf("%w: self attestation: %w", errAttestation, err)
		}
		return nil
	}
	chain, ok := rawChain.([]any)
	if !ok || len(chain) == 0 {
		return fmt.Errorf("%w: empty x5c", errAttestation)
	}
	der, ok := chain[0].([]byte)
	if !ok {
		return fmt.Errorf("%w: x5c entry is not a byte string", errAttestation)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("%w: attestation certificate: %w", errAttestation, err)
	}
	if err := checkAttestationCert(cert, ad.AAGUID); err != nil {
		return err
	}
	if err := verifySignature(alg, cert.PublicKey, signed, sig); err != nil {
		return fmt.Errorf("%w: packed statement: %w", errAttestation, err)
	}
	return nil
}

// checkAttestationCert applies the requirements of section 8.2.1 that do
// not depend on a trust anchor: an X.509 v3 end-entity certificate whose
// AAGUID extension, if present, is not critical and names the
// authenticator's AAGUID.
func checkAttestationCert(cert *x509.Certificate, aaguid [16]byte) error {
	if cert.Version != 3 || cert.BasicConstraintsValid && cert.IsCA {
		return fmt.Errorf("%w: attestation certificate is not a v3 end-entity certificate", errAttestation)
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidAAGUID) {
			continue
		}
		var value []byte
		rest, err := asn1.Unmarshal(ext.Value, &value)
		if err != nil || len(rest) != 0 || ext.Critical || !bytes.Equal(value, aaguid[:]) {
			return fmt.Errorf("%w: attestation certificate AAGUID does not match", errAttestation)
		}
	}
	return nil
}
