package vault

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"strconv"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// Records are the stored, non-secret records of the resources a user can
// assign a saved password to, as their stores keep them: the JSON objects
// of the Python release (profiles.json, jump_hosts.json, socks_proxies.json,
// smb_shares.json).
type Records struct {
	Profiles     []jsontext.Value
	JumpHosts    []jsontext.Value
	SOCKSProxies []jsontext.Value
	SMBShares    []jsontext.Value
	// SMB is false while no store provides SMB shares. Assignments to SMB
	// shares then count as in use, so deleting a password cannot drop
	// them.
	SMB bool
}

// Stores returns the records of a user (provided in cmd/webssh over
// internal/hosts and internal/files/smb).
type Stores interface {
	Records(ctx context.Context, userID int64) (Records, error)
}

// Resource is one resource a saved password can be assigned to, derived
// from its record as credential_service.resources of the Python release
// derived it.
type Resource struct {
	ID   string // public resource id
	Kind ResourceKind
	// Name is the record's name member, null when it has none.
	Name jsontext.Value
	// Password reports auth_type "password" (always for SMB shares).
	Password bool
	Target   Target
	// Fingerprint is Fingerprint(Target), or "" for a record whose fields
	// cannot be represented exactly (for example a port that is not an
	// integer); such a resource never matches an assignment.
	Fingerprint string
	// Page is the record as the credentials page shows it: the stored
	// members with the public id, then kind and, for a saved host with a
	// route, route_fingerprint.
	Page []pyjson.Member
}

// ResourcesFromRecords derives the resources in the order of the Python
// release: saved hosts, jump hosts, SOCKS proxies, SMB shares. A record
// without a string id is skipped; Python could not have listed it.
func ResourcesFromRecords(r Records) []Resource {
	jumps := map[string]jsontext.Value{}
	for _, j := range r.JumpHosts {
		if id, ok := stringMember(j, "id"); ok {
			jumps[id] = j // a later duplicate wins, as in a Python dict
		}
	}
	var out []Resource
	var proxies []Resource
	proxyByID := map[string]Resource{}
	for _, p := range r.SOCKSProxies {
		res, ok := derive(p, ResourceSOCKS, nil)
		if !ok {
			continue
		}
		proxies = append(proxies, res)
		raw, _ := stringMember(p, "id")
		proxyByID[raw] = res
	}
	for _, p := range r.Profiles {
		var route *string
		if v, ok := pyjson.Get(p, "jump_host_id"); ok && truthy(v) {
			fp := emptyFingerprint
			if id, ok := asString(v); ok {
				if j, found := jumps[id]; found {
					fp = rawFingerprint(j)
				}
			}
			route = &fp
		}
		if v, ok := pyjson.Get(p, "socks_proxy_id"); ok && truthy(v) {
			fp := emptyFingerprint
			if id, ok := asString(v); ok {
				if proxy, found := proxyByID[id]; found {
					fp = proxy.Fingerprint
				}
			}
			route = &fp
		}
		if res, ok := derive(p, ResourceSSH, route); ok {
			out = append(out, res)
		}
	}
	for _, j := range r.JumpHosts {
		if res, ok := derive(j, ResourceJump, nil); ok {
			out = append(out, res)
		}
	}
	out = append(out, proxies...)
	for _, s := range r.SMBShares {
		if res, ok := derive(s, ResourceSMB, nil); ok {
			out = append(out, res)
		}
	}
	return out
}

// emptyFingerprint is profile_fingerprint({}): the route fingerprint of a
// saved host whose jump host or proxy no longer exists.
var emptyFingerprint = Fingerprint(Target{})

// rawFingerprint is the fingerprint of an untyped jump host record, as a
// saved host binds its route.
func rawFingerprint(v jsontext.Value) string {
	t, ok := targetOf(v, "", nil)
	if !ok {
		return ""
	}
	return Fingerprint(t)
}

func derive(v jsontext.Value, kind ResourceKind, route *string) (Resource, bool) {
	members, ok := pyjson.Members(v)
	raw, okID := stringMember(v, "id")
	if !ok || !okID {
		return Resource{}, false
	}
	id := ResourceID(kind, raw)
	members = pyjson.Set(members, "id", pyjson.String(id))
	members = pyjson.Set(members, "kind", pyjson.String(string(kind)))
	if kind == ResourceSMB {
		members = pyjson.Set(members, "port", jsontext.Value("445"))
		members = pyjson.Set(members, "auth_type", pyjson.String("password"))
	}
	if route != nil {
		members = pyjson.Set(members, "route_fingerprint", pyjson.String(*route))
	}
	page := pyjson.Object(members)
	res := Resource{ID: id, Kind: kind, Name: memberOr(page, "name"), Page: members}
	auth, _ := stringMember(page, "auth_type")
	res.Password = auth == "password"
	if t, ok := targetOf(page, kind, route); ok {
		res.Target, res.Fingerprint = t, Fingerprint(t)
	}
	return res, true
}

// targetOf reads the fingerprinted fields of a record. ok is false when a
// field holds a value Target cannot represent exactly.
func targetOf(v jsontext.Value, kind ResourceKind, route *string) (Target, bool) {
	t := Target{Kind: kind}
	ok := true
	str := func(name string) *string {
		s, present, good := optString(v, name)
		ok = ok && good
		if !present {
			return nil
		}
		return s
	}
	t.ID, t.Host, t.Username = str("id"), str("host"), str("username")
	t.AuthType, t.KeyID, t.JumpHostID = str("auth_type"), str("key_id"), str("jump_host_id")
	if p, present := pyjson.Get(v, "port"); present && p.Kind() != 'n' {
		n, err := strconv.ParseInt(string(p), 10, 64)
		ok = ok && err == nil && p.Kind() == '0'
		t.Port = &n
	}
	if s, present := pyjson.Get(v, "socks_proxy_id"); present && truthy(s) {
		id, good := asString(s)
		ok = ok && good
		t.SOCKSProxyID = &id
	}
	if kind == ResourceSOCKS {
		if b, present := pyjson.Get(v, "remote_dns"); present {
			value := b.Kind() == 't'
			ok = ok && (b.Kind() == 't' || b.Kind() == 'f')
			t.RemoteDNS = &value
		}
	}
	if kind == ResourceSMB {
		if d, present := pyjson.Get(v, "domain"); present {
			s, good := asString(d)
			ok = ok && good
			t.Domain = &s
		}
		t.Share = str("share")
	}
	if route != nil {
		t.RouteFingerprint = *route
	}
	return t, ok
}

// optString reads a member that is a string or null; good is false for
// any other kind of value.
func optString(v jsontext.Value, name string) (s *string, present, good bool) {
	m, present := pyjson.Get(v, name)
	if !present || m.Kind() == 'n' {
		return nil, present, true
	}
	str, good := asString(m)
	return &str, true, good
}

func stringMember(v jsontext.Value, name string) (string, bool) {
	m, ok := pyjson.Get(v, name)
	if !ok {
		return "", false
	}
	return asString(m)
}

func memberOr(v jsontext.Value, name string) jsontext.Value {
	if m, ok := pyjson.Get(v, name); ok {
		return m
	}
	return jsontext.Value("null")
}

func asString(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

// truthy is Python's bool() of a JSON value.
func truthy(v jsontext.Value) bool {
	switch v.Kind() {
	case 'n', 'f', 0:
		return false
	case '"':
		return string(v) != `""`
	case '0':
		f, err := strconv.ParseFloat(string(v), 64)
		return err != nil || f != 0
	case '[':
		return pyjson.Len(v) > 0
	case '{':
		return pyjson.Len(v) > 0
	}
	return true
}
