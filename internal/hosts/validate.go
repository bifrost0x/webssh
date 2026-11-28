package hosts

import (
	"net/netip"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/idna2003"
)

// Host names are validated as in app/profile_manager.py: an IP address as
// ipaddress.ip_address accepts it, or an ASCII host name of RFC 1123
// labels. Names with other characters were never accepted by the profile,
// jump-host and SOCKS forms, nor by the connect path; a stored one
// (imported or hand-edited) is kept and compared in its IDNA 2003 form,
// as canonicalize_hostname does.

func validHost(raw string) bool {
	host := pyStrip(raw)
	if host == "" {
		return false
	}
	if _, ok := pythonAddr(host); ok {
		return true
	}
	return validHostname(host)
}

// validInputHost is validHost for a host that is saved or imported now:
// an IP address may carry a zone only as netpolicy accepts it (an
// interface name or number on a link-local or interface-local address),
// because netpolicy refuses any other zone when connecting and the zone
// is part of the host-key identity.
func validInputHost(raw string) bool {
	host := pyStrip(raw)
	if addr, ok := pythonAddr(host); ok {
		return zoneAllowed(addr)
	}
	return validHost(host)
}

// zoneAllowed is the zone rule of netpolicy (hostname.go), which this
// package may not import.
func zoneAllowed(addr netip.Addr) bool {
	zone := addr.Zone()
	if zone == "" {
		return true
	}
	if addr.Is4In6() || !(addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast()) || len(zone) > 15 {
		return false
	}
	for i := range len(zone) {
		if c := zone[i]; !isASCIIAlnum(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// pythonAddr parses what ipaddress.ip_address accepts for a string: dotted
// IPv4 without leading zeros and IPv6 with an optional scope that holds
// neither '%' nor '/'.
func pythonAddr(s string) (netip.Addr, bool) {
	if strings.Contains(s, "/") {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	if zone := addr.Zone(); zone != "" && strings.Contains(zone, "%") {
		return netip.Addr{}, false
	}
	return addr, true
}

// validHostname is _HOSTNAME_PATTERN: dot-separated ASCII labels of 1 to 63
// letters, digits and hyphens, no hyphen at either end of a label.
func validHostname(s string) bool {
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !isASCIIAlnum(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// validUsername is USERNAME_PATTERN: 1 to 32 of [A-Za-z0-9_.-].
func validUsername(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !isASCIIAlnum(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// canonicalHost is canonicalize_hostname of app/network_policy.py:
// stripped, one pair of brackets and the trailing dots removed, an IP
// address in its string form, a name converted with IDNA 2003 and in lower
// case. ok is false where Python raises.
func canonicalHost(raw string) (string, bool) {
	value := pyStrip(raw)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") && len(value) >= 2 {
		value = value[1 : len(value)-1]
	}
	value = strings.TrimRight(value, ".")
	if value == "" {
		return "", false
	}
	if addr, ok := pythonAddr(value); ok {
		return addr.String(), true
	}
	encoded, err := idna2003.Encode(value)
	if err != nil {
		return "", false
	}
	canonical := strings.ToLower(encoded)
	if len(canonical) > 253 {
		return "", false
	}
	for label := range strings.SplitSeq(canonical, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := range len(label) {
			if c := label[i]; c != '-' && !isASCIIAlnum(c) {
				return "", false
			}
		}
	}
	return canonical, true
}

// UTF-8 budgets of app/connection_storage_policy.py.
const (
	profileNameMaxBytes      = 512
	profileHostMaxBytes      = 1024
	profileUsernameMaxBytes  = 128
	profileGroupMaxBytes     = 256
	profileReferenceMaxBytes = 128
	profileStartupMaxBytes   = 64 << 10
	jumpHostNameMaxBytes     = 512
	socksNameMaxBytes        = 512
	socksUsernameMaxBytes    = 255
)

const quotaPrefix = "Connection storage quota exceeded: "

func quotaError(message string) error {
	return fault.New(fault.QuotaExceeded, quotaPrefix+message)
}

// fieldBudget is one bounded_text check: the field of the record must be
// text within max UTF-8 bytes, or not larger than the stored value it
// replaces.
type fieldBudget struct {
	field string
	max   int
	label string
}

// checkBudgets is validate_profile, validate_jump_host and
// validate_socks_proxy: absent and null members are skipped where Python
// skips None (skipNull), every other value must be text.
func checkBudgets(r, legacy *record, budgets []fieldBudget, skipNull bool) error {
	for _, b := range budgets {
		v, ok := r.get(b.field)
		if skipNull && (!ok || isNull(v)) {
			continue
		}
		s, isText := asString(v)
		if !isText {
			return quotaError(b.label + " must be text")
		}
		if len(s) <= b.max {
			continue
		}
		if legacy != nil {
			if old, ok := legacy.str(b.field); ok && len(s) <= len(old) {
				continue
			}
		}
		return quotaError(b.label + " is too large")
	}
	return nil
}

var profileBudgets = []fieldBudget{
	{"id", profileReferenceMaxBytes, "profile id"},
	{"name", profileNameMaxBytes, "profile name"},
	{"host", profileHostMaxBytes, "profile host"},
	{"username", profileUsernameMaxBytes, "profile username"},
	{"group", profileGroupMaxBytes, "profile group"},
	{"key_id", profileReferenceMaxBytes, "key reference"},
	{"jump_host_id", profileReferenceMaxBytes, "jump-host reference"},
	{"socks_proxy_id", profileReferenceMaxBytes, "SOCKS-proxy reference"},
	{"command_id", profileReferenceMaxBytes, "command reference"},
	{"command_set_id", profileReferenceMaxBytes, "command-set reference"},
	{"startup_commands", profileStartupMaxBytes, "startup commands"},
	{"parameters_override", profileStartupMaxBytes, "command parameters"},
}

var jumpBudgets = []fieldBudget{
	{"id", profileReferenceMaxBytes, "jump-host id"},
	{"name", jumpHostNameMaxBytes, "jump-host name"},
	{"host", profileHostMaxBytes, "jump-host host"},
	{"username", profileUsernameMaxBytes, "jump-host username"},
	{"key_id", profileReferenceMaxBytes, "key reference"},
}

var socksBudgets = []fieldBudget{
	{"id", profileReferenceMaxBytes, "SOCKS-proxy id"},
	{"name", socksNameMaxBytes, "SOCKS-proxy name"},
	{"host", profileHostMaxBytes, "SOCKS-proxy host"},
	{"username", socksUsernameMaxBytes, "SOCKS-proxy username"},
}
