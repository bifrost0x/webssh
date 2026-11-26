package smb

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// Rules of app/smb_share_manager.py.
var shareIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// knownShareFields are _KNOWN_FIELDS; other members of a stored record
// survive an update unless their name looks like a secret.
var knownShareFields = []string{"id", "name", "host", "share", "domain", "username", "created_at", "updated_at"}

var secretMarkers = []string{"password", "passwd", "passphrase", "credential", "secret", "token"}

// secretField is _is_secret_field: the name, case-folded and reduced to
// [a-z0-9], contains a secret marker.
func secretField(name string) bool {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if 'a' <= r && r <= 'z' || '0' <= r && r <= '9' {
			b.WriteRune(r)
		}
	}
	n := b.String()
	for _, m := range secretMarkers {
		if strings.Contains(n, m) {
			return true
		}
	}
	return false
}

// pySpace is str.isspace: White_Space plus the information separators
// U+001C to U+001F, which Python strips too.
func pySpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

// cleanText is _clean_text: a string, stripped, required or not, at most
// maximum characters, every character printable.
func cleanText(v jsontext.Value, required bool, maximum int) (string, bool) {
	s, ok := jsonString(v)
	if !ok {
		return "", false
	}
	s = strings.TrimFunc(s, pySpace)
	if required && s == "" || utf8.RuneCountInString(s) > maximum {
		return "", false
	}
	for _, r := range s {
		if !pyPrintable(r) {
			return "", false
		}
	}
	return s, true
}

// pyPrintable is str.isprintable for one character: not in the
// categories Other and Separator, except the ASCII space.
func pyPrintable(r rune) bool {
	return r == ' ' || unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// jsonString decodes a JSON string value; anything else is false.
func jsonString(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

// ShareFields are the validated, non-secret fields of a share definition.
type ShareFields struct {
	Name, Host, Share, Domain, Username string
}

// validFields applies _validate_payload to the members of a request or a
// stored record. An absent domain is empty.
func validFields(get func(string) (jsontext.Value, bool)) (ShareFields, bool) {
	var f ShareFields
	var ok bool
	value := func(name string) jsontext.Value { v, _ := get(name); return v }
	if f.Name, ok = cleanText(value("name"), true, 128); !ok {
		return f, false
	}
	host, ok := jsonString(value("host"))
	if !ok {
		return f, false
	}
	canonical, err := netpolicy.CanonicalHost(host)
	if err != nil {
		return f, false
	}
	f.Host = canonical
	if f.Share, ok = jsonString(value("share")); !ok || !ValidShareName(f.Share) {
		return f, false
	}
	if d, present := get("domain"); present {
		if f.Domain, ok = cleanText(d, false, 255); !ok {
			return f, false
		}
	}
	if f.Username, ok = cleanText(value("username"), true, 256); !ok {
		return f, false
	}
	return f, true
}

// validRecord is _valid_share: a stored record without secret members,
// with a valid id, fields that are already in their canonical form and
// both times set.
func validRecord(rec jsontext.Value) bool {
	members, ok := pyjson.Members(rec)
	if !ok {
		return false
	}
	get := func(name string) (jsontext.Value, bool) {
		for _, m := range members {
			if m.Name == name {
				return m.Value, true
			}
		}
		return nil, false
	}
	for _, m := range members {
		if secretField(m.Name) {
			return false
		}
	}
	id, ok := get("id")
	if s, isString := jsonString(id); !ok || !isString || !shareIDPattern.MatchString(s) {
		return false
	}
	f, ok := validFields(get)
	if !ok {
		return false
	}
	for name, want := range map[string]string{"name": f.Name, "host": f.Host, "share": f.Share, "username": f.Username} {
		if s, _ := jsonString(func() jsontext.Value { v, _ := get(name); return v }()); s != want {
			return false
		}
	}
	if d, present := get("domain"); present {
		if s, _ := jsonString(d); s != f.Domain {
			return false
		}
	}
	for _, name := range []string{"created_at", "updated_at"} {
		v, _ := get(name)
		if s, ok := jsonString(v); !ok || s == "" {
			return false
		}
	}
	return true
}
