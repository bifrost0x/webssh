package hosts

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"math/big"
	"strings"
	"unicode"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// duplicateProfile is the skip_duplicate rule of upsert_profile: a saved
// host with the same name (trimmed and case-folded, the rule of every
// save since 3.4) or the same host, port, username, jump host and SOCKS5
// proxy.
func duplicateProfile(profiles []record, validated *record) bool {
	name := foldName(validated.text("name"))
	for i := range profiles {
		existing := &profiles[i]
		if foldName(existing.text("name")) == name {
			return true
		}
		same := true
		for _, field := range []string{"host", "port", "username", "jump_host_id", "socks_proxy_id"} {
			a, _ := existing.get(field)
			b, _ := validated.get(field)
			if !pyEqual(a, b) {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// foldText approximates str.casefold(): simple case folding plus ß.
func foldText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 'ß', 'ẞ':
			b.WriteString("ss")
		default:
			b.WriteRune(unicode.ToLower(unicode.ToUpper(r)))
		}
	}
	return b.String()
}

// pyEqual is == of two decoded JSON values as dict.get returns them: an
// absent member and null are both None; numbers and booleans compare by
// value (True == 1, 22 == 22.0); strings, lists and objects exactly.
func pyEqual(a, b jsontext.Value) bool {
	if len(a) == 0 {
		a = jsonNull
	}
	if len(b) == 0 {
		b = jsonNull
	}
	na, aNum := numberValue(a)
	nb, bNum := numberValue(b)
	if aNum || bNum {
		return aNum && bNum && na.Cmp(nb) == 0
	}
	if a.Kind() == '"' && b.Kind() == '"' {
		sa, _ := asString(a)
		sb, _ := asString(b)
		return sa == sb
	}
	return string(a) == string(b)
}

func numberValue(v jsontext.Value) (*big.Rat, bool) {
	switch v.Kind() {
	case 't':
		return big.NewRat(1, 1), true
	case 'f':
		return new(big.Rat), true
	case '0':
		r, ok := new(big.Rat).SetString(string(v))
		return r, ok
	}
	return nil, false
}

// ImportOutcome is the result of importing one previewed host.
type ImportOutcome struct {
	ID        string // set when imported
	Duplicate bool   // a saved host has the same name or endpoint
	Err       error  // the refusal shown to the user otherwise
}

// ImportProfile creates one host from an import (upsert_profile with
// skip_duplicate). It never updates a saved host.
func (s *Service) ImportProfile(ctx context.Context, owner int64, req protocol.HostsProfileSave) ImportOutcome {
	saved, err := s.saveProfile(ctx, owner, req, true, nil)
	switch {
	case errors.Is(err, errDuplicateProfile):
		return ImportOutcome{Duplicate: true}
	case err != nil:
		return ImportOutcome{Err: err}
	}
	id, _ := pyjson.Get(saved, "id")
	text, _ := asString(id)
	return ImportOutcome{ID: text}
}

// importPayload is the payload the import route passes to upsert_profile
// for one selected row.
func importPayload(row *record, sel importSelection) protocol.HostsProfileSave {
	get := func(field string) jsontext.Value {
		v, _ := row.get(field)
		return v
	}
	username := get("username")
	if sel.Username != nil {
		username = jsonString(*sel.Username)
	}
	auth := "password"
	switch {
	case row.text("auth_type") == "tailscale":
		auth = "tailscale"
	case sel.KeyID != nil && *sel.KeyID != "":
		auth = "key"
	}
	optional := func(v *string) jsontext.Value {
		if v == nil {
			return jsonNull
		}
		return jsonString(*v)
	}
	return protocol.HostsProfileSave{
		Name: get("name"), Host: get("host"), Port: get("port"), Username: username,
		Group: get("group"), Favorite: get("favorite"), UseTmux: get("use_tmux"),
		Herdr: get("herdr"), UseHerdr: get("use_herdr"), PlatformIcon: get("platform_icon"),
		RoleOverride: get("role_override"), AuthType: jsonString(auth),
		KeyID: optional(sel.KeyID), JumpHostID: optional(sel.JumpHostID), StartupMode: jsonString("none"),
	}
}

// importSelection is one entry of "selections".
type importSelection struct {
	Index                       int
	Username, KeyID, JumpHostID *string
}

var errMappingMissing = fault.New(fault.ValidationError, "Required mapping is missing.")

// missingMapping is the route's check before saving: a row that needs a
// key or a jump host must have one mapped.
func missingMapping(row *record, sel importSelection) bool {
	requiresKey, _ := row.get("requires_key")
	requiresJump, _ := row.get("requires_jump")
	noKey := sel.KeyID == nil || *sel.KeyID == ""
	noJump := sel.JumpHostID == nil || *sel.JumpHostID == ""
	return (truthy(requiresKey) && noKey) || (truthy(requiresJump) && noJump)
}

var (
	errSelections     = exchangeError("Choose up to 100 hosts.")
	errSelection      = exchangeError("Invalid host selection.")
	errBlockedImport  = exchangeError("Unsupported configuration cannot be imported.")
	errMapping        = exchangeError("Invalid host mapping.")
	selectionMembers  = map[string]bool{"index": true, "username": true, "key_id": true, "jump_host_id": true}
	selectionMappings = []string{"username", "key_id", "jump_host_id"}
)

// readSelections checks every selection before anything is stored, in
// the order of the Python route.
func readSelections(raw jsontext.Value, rows []record) ([]importSelection, error) {
	items, ok := pyjson.Items(raw)
	if !ok || len(items) > exchangeMaxRecords {
		return nil, errSelections
	}
	seen := map[int]bool{}
	out := make([]importSelection, 0, len(items))
	for _, item := range items {
		members, ok := pyjson.Members(item)
		if !ok {
			return nil, errSelection
		}
		for _, m := range members {
			if !selectionMembers[m.Name] {
				return nil, errSelection
			}
		}
		indexValue, _ := pyjson.Get(item, "index")
		index, ok := asInt(indexValue)
		if !ok || index < 0 || index >= int64(len(rows)) || seen[int(index)] {
			return nil, errSelection
		}
		seen[int(index)] = true
		if v, _ := rows[index].get("blocked"); isTrue(v) {
			return nil, errBlockedImport
		}
		sel := importSelection{Index: int(index)}
		for _, field := range selectionMappings {
			v, present := pyjson.Get(item, field)
			if !present {
				continue
			}
			s, ok := asString(v)
			if !ok || pyLen(s) > 128 {
				return nil, errMapping
			}
			switch field {
			case "username":
				sel.Username = &s
			case "key_id":
				sel.KeyID = &s
			default:
				sel.JumpHostID = &s
			}
		}
		out = append(out, sel)
	}
	return out, nil
}
