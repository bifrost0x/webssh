package legacy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"testing"
)

type webauthnVector struct {
	CredentialRowID   int64  `json:"credential_row_id"`
	Name              string `json:"name"`
	COSEAlg           int64  `json:"cose_alg"`
	StoredSignCount   int64  `json:"stored_sign_count"`
	AssertionCount    int64  `json:"assertion_sign_count"`
	ChallengeB64URL   string `json:"challenge_b64url"`
	ExpectedOrigin    string `json:"expected_origin"`
	ExpectedRPID      string `json:"expected_rp_id"`
	AssertionResponse struct {
		RawID    string `json:"rawId"`
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			ClientDataJSON    string `json:"clientDataJSON"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle"`
		} `json:"response"`
	} `json:"assertion_response"`
	Flags map[string]bool `json:"flags"`
}

func b64url(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// prototypeAssertion is a minimal WebAuthn assertion check (W3C WebAuthn
// Level 3, section 7.2, steps relevant to a stored credential). It exists
// to measure the effort of an own implementation for K4; the sign-in
// phase decides on the final implementation.
type prototypeAssertion struct {
	rpID, origin string
	challenge    []byte
	userID       int64
}

func (p prototypeAssertion) verify(key crypto.PublicKey, alg int64, storedCount int64, authData, clientData, sig []byte, userHandle string) (uint32, error) {
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil {
		return 0, err
	}
	challenge, err := b64url(cd.Challenge)
	if err != nil || cd.Type != "webauthn.get" || !bytes.Equal(challenge, p.challenge) || cd.Origin != p.origin || cd.CrossOrigin {
		return 0, errors.New("client data mismatch")
	}
	if userHandle != strconv.FormatInt(p.userID, 10) {
		return 0, errors.New("user handle mismatch")
	}
	rpHash := sha256.Sum256([]byte(p.rpID))
	if len(authData) < 37 || !bytes.Equal(authData[:32], rpHash[:]) {
		return 0, errors.New("rp id hash mismatch")
	}
	if flags := authData[32]; flags&0x01 == 0 || flags&0x04 == 0 {
		return 0, errors.New("user presence or verification missing")
	}
	count := binary.BigEndian.Uint32(authData[33:37])
	if storedCount > 0 && int64(count) <= storedCount {
		return 0, errors.New("counter did not advance")
	}
	cdHash := sha256.Sum256(clientData)
	signed := append(bytes.Clone(authData), cdHash[:]...)
	digest := sha256.Sum256(signed)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if alg != COSEAlgES256 || !ecdsa.VerifyASN1(k, digest[:], sig) {
			return 0, errors.New("ES256 signature invalid")
		}
	case *rsa.PublicKey:
		if alg != COSEAlgRS256 || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return 0, errors.New("RS256 signature invalid")
		}
	case ed25519.PublicKey:
		if alg != COSEAlgEdDSA || !ed25519.Verify(k, signed, sig) {
			return 0, errors.New("EdDSA signature invalid")
		}
	default:
		return 0, fmt.Errorf("unsupported key %T", key)
	}
	return count, nil
}

func TestGoldenPasskeys(t *testing.T) {
	t.Parallel()
	passkeys, err := golden.source.Passkeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]Passkey{}
	for _, p := range passkeys {
		byID[p.ID] = p
	}
	deleted := golden.manifest.Values.EdgeCases.PasskeyDeleted.ID
	if _, ok := byID[deleted]; ok {
		t.Fatal("deleted passkey is present")
	}
	owner := goldenUserByName(t, "passkey_user").ID
	algs := map[int64]bool{}
	for _, vec := range golden.manifest.Values.WebAuthnVectors {
		if vec.CredentialRowID == deleted {
			continue
		}
		t.Run(vec.Name, func(t *testing.T) {
			t.Parallel()
			pk, ok := byID[vec.CredentialRowID]
			rawID, _ := b64url(vec.AssertionResponse.RawID)
			if !ok || pk.Name != vec.Name || pk.Algorithm != vec.COSEAlg || pk.SignCount != vec.StoredSignCount ||
				pk.UserID != owner || !bytes.Equal(pk.CredentialID, rawID) {
				t.Fatalf("row %+v", pk)
			}
			r := vec.AssertionResponse.Response
			authData, err1 := b64url(r.AuthenticatorData)
			clientData, err2 := b64url(r.ClientDataJSON)
			sig, err3 := b64url(r.Signature)
			handle, err4 := b64url(r.UserHandle)
			challenge, err5 := b64url(vec.ChallengeB64URL)
			if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
				t.Fatal(err)
			}
			check := prototypeAssertion{rpID: vec.ExpectedRPID, origin: vec.ExpectedOrigin, challenge: challenge, userID: owner}
			count, err := check.verify(pk.PublicKey, pk.Algorithm, pk.SignCount, authData, clientData, sig, string(handle))
			if err != nil || int64(count) != vec.AssertionCount {
				t.Fatalf("assertion: count %d, %v; want %d", count, err, vec.AssertionCount)
			}
			if be, bs := authData[32]&0x08 != 0, authData[32]&0x10 != 0; be != vec.Flags["BE"] || bs != vec.Flags["BS"] {
				t.Fatalf("backup flags BE=%v BS=%v", be, bs)
			}
			tampered := bytes.Clone(sig)
			tampered[len(tampered)-1] ^= 1
			if _, err := check.verify(pk.PublicKey, pk.Algorithm, pk.SignCount, authData, clientData, tampered, string(handle)); err == nil {
				t.Fatal("tampered signature accepted")
			}
			wrongOrigin := check
			wrongOrigin.origin = "https://attacker.test"
			if _, err := wrongOrigin.verify(pk.PublicKey, pk.Algorithm, pk.SignCount, authData, clientData, sig, string(handle)); err == nil {
				t.Fatal("wrong origin accepted")
			}
			if vec.AssertionCount > 0 {
				if _, err := check.verify(pk.PublicKey, pk.Algorithm, vec.AssertionCount, authData, clientData, sig, string(handle)); err == nil {
					t.Fatal("replayed counter accepted")
				}
			}
		})
		algs[vec.COSEAlg] = true
	}
	if len(algs) != 3 || !algs[COSEAlgES256] || !algs[COSEAlgRS256] || !algs[COSEAlgEdDSA] {
		t.Fatalf("algorithms covered: %v", algs)
	}
}
