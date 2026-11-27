package smb

import (
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// SaveRequestOf reads a share definition from a JSON object as
// _validate_payload did, for a share created together with its saved
// password (create_for_resource): a member that looks like a secret
// refuses the whole payload; other unknown members are ignored.
func SaveRequestOf(payload jsontext.Value) (SaveRequest, error) {
	members, ok := pyjson.Members(payload)
	if !ok {
		return SaveRequest{}, fault.New(fault.ValidationError, "Invalid SMB share data")
	}
	var r SaveRequest
	for _, m := range members {
		if secretField(m.Name) {
			return SaveRequest{}, fault.New(fault.ValidationError, "Passwords cannot be saved")
		}
		switch m.Name {
		case "id":
			r.ID = m.Value
		case "name":
			r.Name = m.Value
		case "host":
			r.Host = m.Value
		case "share":
			r.Share = m.Value
		case "domain":
			r.Domain = m.Value
		case "username":
			r.Username = m.Value
		}
	}
	return r, nil
}
