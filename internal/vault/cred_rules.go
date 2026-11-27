package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// textValue is text() of app/automation_store.py: a string without NUL,
// not blank unless empty is allowed, at most maximum UTF-8 bytes. Any
// other value is invalid_request.
func textValue(v jsontext.Value, maximum int, empty bool) (string, error) {
	s, ok := asString(v)
	if !ok || !validText(s, maximum, empty) {
		return "", fault.New(fault.InvalidRequest, "")
	}
	return s, nil
}

func validText(s string, maximum int, empty bool) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0) && len(s) <= maximum &&
		(empty || strings.TrimFunc(s, pyIsSpace) != "")
}

// pyIsSpace is str.isspace() for one character.
func pyIsSpace(r rune) bool {
	switch r {
	case 0x1c, 0x1d, 0x1e, 0x1f:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r)
}

// randomHex is secrets.token_hex(n).
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

// pyISOTime is datetime.now(timezone.utc).isoformat(): microseconds only
// when they are not zero.
func pyISOTime(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

// canonical returns the RFC 8785 form of a JSON value. Two values with
// the same meaning (member order, number spelling) give the same text, so
// it stands in for Python's dict equality and for digest().
func canonical(v jsontext.Value) (string, bool) {
	c := v.Clone()
	if err := c.Canonicalize(); err != nil {
		return "", false
	}
	return string(c), true
}

func digestOf(v jsontext.Value) (string, bool) {
	c, ok := canonical(v)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:]), true
}

var (
	jsonNull = jsontext.Value("null")
	jsonTrue = jsontext.Value("true")
)

// normalizeTarget is CredentialService._normalize_target: the
// security-relevant fields of a one-off target with the route given either
// by id or as the nested saved route, in canonical JSON. A contradicting
// or unusable route is credential_target_changed.
func normalizeTarget(v jsontext.Value) (string, error) {
	changed := fault.New(fault.CredentialTargetChanged, "")
	if v.Kind() != '{' {
		return "", changed
	}
	get := func(name string) jsontext.Value {
		if m, ok := pyjson.Get(v, name); ok {
			return m
		}
		return jsonNull
	}
	share := get("share")
	isSMB := truthy(share)
	kind, _ := asString(get("kind"))
	isSOCKS := kind == "socks"
	jump := get("jump_host_id")
	socks := jsonNull
	if !isSOCKS {
		socks = get("socks_proxy_id")
	}
	if nested := get("proxy_jump"); nested.Kind() != 'n' {
		saved, err := savedRoute(nested, "jump_host_id")
		if err != nil {
			return "", err
		}
		if truthy(jump) && !sameJSON(jump, saved) {
			return "", changed
		}
		jump = saved
	}
	if nested := get("socks_proxy"); nested.Kind() != 'n' {
		saved, err := savedRoute(nested, "socks_proxy_id")
		if err != nil {
			return "", err
		}
		if isSOCKS || (truthy(socks) && !sameJSON(socks, saved)) {
			return "", changed
		}
		socks = saved
	}
	auth, _ := asString(get("auth_type"))
	if (truthy(socks) && (truthy(jump) || isSMB || auth == "tailscale")) ||
		(isSOCKS && (truthy(jump) || isSMB)) ||
		(jump.Kind() != 'n' && jump.Kind() != '"') || (socks.Kind() != 'n' && socks.Kind() != '"') {
		return "", changed
	}
	port := get("port")
	if !truthy(port) {
		port = jsontext.Value("22")
		switch {
		case isSMB:
			port = jsontext.Value("445")
		case isSOCKS:
			port = jsontext.Value("1080")
		}
	}
	authType := get("auth_type")
	if !truthy(authType) {
		authType = pyjson.String("password")
	}
	domain, shareOut := jsonNull, jsonNull
	if isSMB {
		domain, shareOut = get("domain"), share
		if !truthy(domain) {
			domain = pyjson.String("")
		}
	}
	members := []pyjson.Member{
		{Name: "host", Value: get("host")}, {Name: "port", Value: port}, {Name: "username", Value: get("username")},
		{Name: "auth_type", Value: authType}, {Name: "key_id", Value: get("key_id")}, {Name: "jump_host_id", Value: jump},
		{Name: "domain", Value: domain}, {Name: "share", Value: shareOut},
	}
	if truthy(socks) {
		members = append(members, pyjson.Member{Name: "socks_proxy_id", Value: socks})
	}
	if isSOCKS {
		remoteDNS, ok := pyjson.Get(v, "remote_dns")
		if !ok {
			remoteDNS = jsonTrue
		}
		if remoteDNS.Kind() != 't' && remoteDNS.Kind() != 'f' {
			return "", changed
		}
		members = append(members, pyjson.Member{Name: "kind", Value: pyjson.String("socks")}, pyjson.Member{Name: "remote_dns", Value: remoteDNS})
	}
	out, ok := canonical(pyjson.Object(members))
	if !ok {
		return "", changed
	}
	return out, nil
}

// savedRoute is _saved_route of credential_connections.py: the id of a
// nested saved route, which must be an object with a non-empty string id.
func savedRoute(route jsontext.Value, field string) (jsontext.Value, error) {
	id, ok := pyjson.Get(route, field)
	if route.Kind() != '{' || !ok || id.Kind() != '"' || string(id) == `""` {
		return nil, fault.New(fault.CredentialTargetChanged, "")
	}
	return id, nil
}

func sameJSON(a, b jsontext.Value) bool {
	x, okA := canonical(a)
	y, okB := canonical(b)
	return okA && okB && x == y
}

// targetJSON is a connection target as the JSON object _connection_target
// of the Python release hands to _normalize_target.
func targetJSON(t Target) jsontext.Value {
	str := func(s *string) jsontext.Value {
		if s == nil {
			return jsonNull
		}
		return pyjson.String(*s)
	}
	members := []pyjson.Member{
		{Name: "host", Value: str(t.Host)}, {Name: "username", Value: str(t.Username)},
		{Name: "auth_type", Value: str(t.AuthType)}, {Name: "key_id", Value: str(t.KeyID)},
		{Name: "jump_host_id", Value: str(t.JumpHostID)}, {Name: "socks_proxy_id", Value: str(t.SOCKSProxyID)},
		{Name: "domain", Value: str(t.Domain)}, {Name: "share", Value: str(t.Share)},
		{Name: "kind", Value: pyjson.String(string(t.Kind))},
	}
	if t.Port != nil {
		members = append(members, pyjson.Member{Name: "port", Value: jsontext.Value(jsonInt(t.Port))})
	}
	if t.RemoteDNS != nil {
		members = append(members, pyjson.Member{Name: "remote_dns", Value: jsontext.Value(map[bool]string{true: "true", false: "false"}[*t.RemoteDNS])})
	}
	return pyjson.Object(members)
}

// pythonDigest is digest() of app/automation_store.py for a value of
// JSON objects, arrays, strings, integers, booleans and null: SHA-256 of
// json.dumps with sorted keys, compact separators and ASCII escapes.
// Floats are refused (Python's repr is not reproduced).
func pythonDigest(v jsontext.Value) (string, bool) {
	var b strings.Builder
	if !writePython(&b, v) {
		return "", false
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:]), true
}

func writePython(b *strings.Builder, v jsontext.Value) bool {
	switch v.Kind() {
	case 'n', 't', 'f':
		b.Write(v)
	case '"':
		s, ok := asString(v)
		if !ok {
			return false
		}
		b.WriteString(pyjson.Quote(s))
	case '0':
		if strings.ContainsAny(string(v), ".eE") {
			return false
		}
		b.Write(v)
	case '[':
		items, ok := pyjson.Items(v)
		if !ok {
			return false
		}
		b.WriteByte('[')
		for i, item := range items {
			if i > 0 {
				b.WriteByte(',')
			}
			if !writePython(b, item) {
				return false
			}
		}
		b.WriteByte(']')
	case '{':
		members, ok := pyjson.Members(v)
		if !ok {
			return false
		}
		slices.SortFunc(members, func(x, y pyjson.Member) int { return strings.Compare(x.Name, y.Name) })
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(pyjson.Quote(m.Name))
			b.WriteByte(':')
			if !writePython(b, m.Value) {
				return false
			}
		}
		b.WriteByte('}')
	default:
		return false
	}
	return true
}
