package automation

import (
	"encoding/json/jsontext"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/vault"
)

// Limits of a selection (_inventory).
const (
	maxSelection    = 100
	maxSelectionID  = 128
	maxRunHostCount = 50
)

// hop is one frozen SSH hop of a run: a saved host or its jump host, as
// the user reviewed it.
type hop struct {
	ResourceID  string
	Fingerprint string
	Target      vault.Target
	Name        string
	Host        string
	Port        int64
	Username    string
	Group       *string
	AuthType    string
	KeyID       string
	JumpHostID  string
	SOCKS       bool
	Page        []pyjson.Member
}

// Frozen is one target of a reviewed run: the saved host and its jump
// host as they were at the review.
type Frozen struct {
	hop
	Route *hop
}

func hopOf(r vault.Resource) hop {
	page := pyjson.Object(r.Page)
	str := func(name string) string {
		v, _ := pyjson.Get(page, name)
		s, _ := pyString(v)
		return s
	}
	h := hop{ResourceID: r.ID, Fingerprint: r.Fingerprint, Target: r.Target, Page: r.Page,
		Name: str("name"), Host: str("host"), Username: str("username"), AuthType: str("auth_type"),
		KeyID: str("key_id"), JumpHostID: str("jump_host_id"), Port: 22}
	if v, ok := pyjson.Get(page, "port"); ok {
		if n, isInt := pyInt(v); isInt {
			h.Port = n
		} else {
			h.Port = -1
		}
	}
	if v, ok := pyjson.Get(page, "group"); ok {
		if s, isStr := pyString(v); isStr {
			h.Group = &s
		}
	}
	if v, ok := pyjson.Get(page, "socks_proxy_id"); ok && v.Kind() != 'n' && string(v) != `""` && string(v) != "false" {
		h.SOCKS = true
	}
	if v, ok := pyjson.Get(page, "jump_host_id"); ok && (v.Kind() == 'n' || string(v) == `""`) {
		h.JumpHostID = ""
	}
	return h
}

// supported is supported_login: key or password sign-in with a user
// name, no SOCKS5 proxy, no gateway form ("user:target"), and the
// display fields the run history keeps.
func (h *hop) supported() bool {
	if h == nil || (h.AuthType != "key" && h.AuthType != "password") || h.SOCKS {
		return false
	}
	return h.Username != "" && !strings.Contains(h.Username, ":") &&
		h.Port >= 1 && h.Port <= 65535 && h.Host != "" && len(h.Host) <= 512 && len(h.Username) <= 512 &&
		len(h.Name) <= 512 && (h.Group == nil || len(*h.Group) <= 512)
}

// inventory is the user's saved hosts with their jump hosts.
type inventory struct {
	profiles []hop
	routes   map[string]hop // by resource id "jump:<id>"
}

func newInventory(records vault.Records) inventory {
	inv := inventory{routes: map[string]hop{}}
	for _, r := range vault.ResourcesFromRecords(records) {
		switch r.Kind {
		case vault.ResourceSSH:
			inv.profiles = append(inv.profiles, hopOf(r))
		case vault.ResourceJump:
			inv.routes[r.ID] = hopOf(r)
		}
	}
	return inv
}

func (inv inventory) route(h hop) *hop {
	if h.JumpHostID == "" {
		return nil
	}
	r, ok := inv.routes[vault.ResourceID(vault.ResourceJump, h.JumpHostID)]
	if !ok {
		return nil
	}
	return &r
}

func (inv inventory) byID(id string) (hop, bool) {
	i := slices.IndexFunc(inv.profiles, func(h hop) bool { return h.ResourceID == id })
	if i < 0 {
		return hop{}, false
	}
	return inv.profiles[i], true
}

// targetSupported is the "supported" flag of the state: the host and,
// where it has one, its jump host.
func (inv inventory) targetSupported(h hop) bool {
	if !h.supported() {
		return false
	}
	if h.JumpHostID == "" {
		return true
	}
	return inv.route(h).supported()
}

// selection is the body of a review: saved host ids and group names.
type selection struct {
	ProfileIDs []string
	Groups     []string
}

func parseSelection(body jsontext.Value) (selection, error) {
	var s selection
	for name, dst := range map[string]*[]string{"profile_ids": &s.ProfileIDs, "groups": &s.Groups} {
		v, ok := pyjson.Get(body, name)
		if !ok {
			continue
		}
		items, isList := pyjson.Items(v)
		if !isList {
			return selection{}, Fail("invalid_targets")
		}
		for _, item := range items {
			str, isStr := pyString(item)
			if !isStr || len([]rune(str)) > maxSelectionID {
				return selection{}, Fail("invalid_targets")
			}
			*dst = append(*dst, str)
		}
	}
	if len(s.ProfileIDs)+len(s.Groups) > maxSelection {
		return selection{}, Fail("invalid_targets")
	}
	return s, nil
}

// freeze is _inventory: the selected saved hosts, in the order of the
// library, each with its jump host. Every id and group must exist, at
// most 50 hosts, every host and jump host supported.
func (inv inventory) freeze(sel selection) ([]Frozen, error) {
	groups := map[string]bool{}
	for _, p := range inv.profiles {
		if p.Group != nil && *p.Group != "" {
			groups[*p.Group] = true
		}
	}
	for _, id := range sel.ProfileIDs {
		if _, ok := inv.byID(id); !ok {
			return nil, Fail("invalid_targets")
		}
	}
	for _, g := range sel.Groups {
		if !groups[g] {
			return nil, Fail("invalid_targets")
		}
	}
	selected := map[string]bool{}
	for _, id := range sel.ProfileIDs {
		selected[id] = true
	}
	for _, p := range inv.profiles {
		if p.Group != nil && slices.Contains(sel.Groups, *p.Group) {
			selected[p.ResourceID] = true
		}
	}
	if len(selected) < 1 || len(selected) > maxRunHostCount {
		return nil, Fail("invalid_targets")
	}
	var out []Frozen
	for _, p := range inv.profiles {
		if !selected[p.ResourceID] {
			continue
		}
		if !p.supported() {
			return nil, Fail("unsupported_target")
		}
		f := Frozen{hop: p}
		if p.JumpHostID != "" {
			r := inv.route(p)
			if !r.supported() {
				return nil, Fail("unsupported_target")
			}
			f.Route = r
		}
		out = append(out, f)
	}
	return out, nil
}

// hops lists every frozen SSH hop of the targets once: each jump host
// before its first target (connection_resources).
func hops(targets []Frozen) []hop {
	seen := map[string]bool{}
	var out []hop
	for _, t := range targets {
		for _, h := range []*hop{t.Route, &t.hop} {
			if h != nil && !seen[h.ResourceID] {
				seen[h.ResourceID] = true
				out = append(out, *h)
			}
		}
	}
	return out
}

// display is display_target as the history and the review show it.
func (h hop) display() []pyjson.Member {
	return []pyjson.Member{
		{Name: "id", Value: pyjson.String(h.ResourceID)},
		{Name: "name", Value: pyjson.String(h.Name)},
		{Name: "host", Value: pyjson.String(h.Host)},
		{Name: "port", Value: jsontext.Value(itoa(h.Port))},
		{Name: "username", Value: pyjson.String(h.Username)},
		{Name: "group", Value: strOrNull(h.Group)},
	}
}
