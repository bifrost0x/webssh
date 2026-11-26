package webauthn

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strconv"
)

// The options JSON is the one py_webauthn's options_to_json produced, so
// webauthn.js decodes it unchanged: base64url byte values, the same
// members in the same order, a 60 s timeout hint and required user
// verification.

// CeremonyTimeout is the timeout hint of the options in milliseconds.
const CeremonyTimeout = 60000

type descriptorJSON struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type creationOptions struct {
	RP struct {
		Name string `json:"name"`
		ID   string `json:"id,omitempty"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Challenge        string `json:"challenge"`
	PubKeyCredParams []struct {
		Type string `json:"type"`
		Alg  int64  `json:"alg"`
	} `json:"pubKeyCredParams"`
	Timeout                int              `json:"timeout"`
	ExcludeCredentials     []descriptorJSON `json:"excludeCredentials"`
	AuthenticatorSelection struct {
		ResidentKey        string `json:"residentKey"`
		RequireResidentKey bool   `json:"requireResidentKey"`
		UserVerification   string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Attestation string `json:"attestation"`
	// Ceremony names this registration; register/verify sends it back.
	Ceremony string `json:"ceremony"`
}

type requestOptions struct {
	Challenge        string           `json:"challenge"`
	Timeout          int              `json:"timeout"`
	RPID             string           `json:"rpId"`
	AllowCredentials []descriptorJSON `json:"allowCredentials"`
	UserVerification string           `json:"userVerification"`
}

// UserHandle is the user.id of a registration: the account id in ASCII
// decimal, as the Python release registered it (invariant I-02).
func UserHandle(userID int64) string { return strconv.FormatInt(userID, 10) }

func descriptors(ids [][]byte) []descriptorJSON {
	out := make([]descriptorJSON, 0, len(ids))
	for _, id := range ids {
		out = append(out, descriptorJSON{ID: encodeB64URL(id), Type: "public-key"})
	}
	return out
}

// creationJSON builds the registration options: a discoverable credential
// with user verification, attestation "none", and the given credentials
// excluded.
func (rp RelyingParty) creationJSON(userID int64, username string, challenge []byte, exclude [][]byte, ceremony string) (jsontext.Value, error) {
	var o creationOptions
	o.RP.Name, o.RP.ID = rp.Name, rp.ID
	o.User.ID = encodeB64URL([]byte(UserHandle(userID)))
	o.User.Name, o.User.DisplayName = username, username
	o.Challenge = encodeB64URL(challenge)
	for _, alg := range algorithms() {
		o.PubKeyCredParams = append(o.PubKeyCredParams, struct {
			Type string `json:"type"`
			Alg  int64  `json:"alg"`
		}{"public-key", alg})
	}
	o.Timeout = CeremonyTimeout
	o.ExcludeCredentials = descriptors(exclude)
	o.AuthenticatorSelection.ResidentKey = "required"
	o.AuthenticatorSelection.RequireResidentKey = true
	o.AuthenticatorSelection.UserVerification = "required"
	o.Attestation = FormatNone
	o.Ceremony = ceremony
	return marshalOptions(o)
}

// requestJSON builds the assertion options; allow is empty for a sign-in
// without a user name.
func (rp RelyingParty) requestJSON(challenge []byte, allow [][]byte) (jsontext.Value, error) {
	return marshalOptions(requestOptions{
		Challenge: encodeB64URL(challenge), Timeout: CeremonyTimeout, RPID: rp.ID,
		AllowCredentials: descriptors(allow), UserVerification: "required",
	})
}

func marshalOptions(v any) (jsontext.Value, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("webauthn: options: %w", err)
	}
	return b, nil
}
