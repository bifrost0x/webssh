package webauthn

import (
	"crypto/subtle"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
)

// Client data types.
const (
	typeCreate = "webauthn.create"
	typeGet    = "webauthn.get"
)

var errClientData = errors.New("webauthn: client data does not match")

type clientData struct {
	Type        string  `json:"type"`
	Challenge   string  `json:"challenge"`
	Origin      string  `json:"origin"`
	CrossOrigin *bool   `json:"crossOrigin"`
	TopOrigin   *string `json:"topOrigin"`
	// TokenBinding is only checked for its status, as the Python release
	// did; browsers no longer send it.
	TokenBinding *struct {
		Status string `json:"status"`
	} `json:"tokenBinding"`
}

// checkClientData verifies clientDataJSON (Level 3, section 7.1 steps 7 to
// 11 and section 7.2 steps 10 to 14): valid JSON without duplicate
// members, the ceremony type, the challenge byte for byte and the origin
// exactly as configured. WebSSH is never embedded in another site, so
// crossOrigin must be absent or false and topOrigin absent.
func checkClientData(raw []byte, wantType string, challenge []byte, origin string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("%w: %w", errClientData, err)
	}
	if cd.Type != wantType {
		return fmt.Errorf("%w: type %q", errClientData, cd.Type)
	}
	got, err := decodeB64URL(cd.Challenge)
	if err != nil || len(challenge) == 0 || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return fmt.Errorf("%w: challenge", errClientData)
	}
	if cd.Origin != origin {
		return fmt.Errorf("%w: origin %q", errClientData, cd.Origin)
	}
	if cd.CrossOrigin != nil && *cd.CrossOrigin || cd.TopOrigin != nil {
		return fmt.Errorf("%w: cross-origin ceremony", errClientData)
	}
	if tb := cd.TokenBinding; tb != nil && tb.Status != "present" && tb.Status != "supported" {
		return fmt.Errorf("%w: token binding status %q", errClientData, tb.Status)
	}
	return nil
}

// decodeB64URL decodes base64url without padding, as browsers send it;
// trailing padding is tolerated, like the Python release did.
func decodeB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(strings.TrimRight(s, "="))
}

func encodeB64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
