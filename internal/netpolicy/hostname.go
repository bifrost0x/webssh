package netpolicy

import (
	"net/netip"
	"strings"
	"unicode"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/idna2003"
)

// Host name refusals. The texts are safe to show.
var (
	errHostRequired = fault.New(fault.InvalidValue, "Host is required.")
	errHostFormat   = fault.New(fault.InvalidValue, "Invalid host format.")
)

// CanonicalHost returns the form used for policy decisions and host-key
// identity, exactly as app/network_policy.py canonicalize_hostname: the
// value stripped, one pair of brackets and all trailing dots removed, an
// IP literal in Python's string form, a name converted with the IDNA 2003
// codec (internal/idna2003) and lower-cased, with RFC 1123 labels. Host
// keys of the Python release are stored under this form.
func CanonicalHost(raw string) (string, error) {
	value := pyStrip(raw)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") && len(value) >= 2 {
		value = value[1 : len(value)-1]
	}
	value = strings.TrimRight(value, ".")
	if value == "" {
		return "", errHostRequired
	}
	if addr, ok := parsePythonAddr(value); ok {
		return pythonAddrString(addr), nil
	}
	encoded, err := idna2003.Encode(value)
	if err != nil {
		return "", errHostFormat
	}
	canonical := strings.ToLower(encoded)
	if len(canonical) > 253 {
		return "", errHostFormat
	}
	for label := range strings.SplitSeq(canonical, ".") {
		if !validLabel(label) {
			return "", errHostFormat
		}
	}
	return canonical, nil
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := range len(label) {
		c := label[i]
		if c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// parsePythonAddr accepts what ipaddress.ip_address accepts for a string:
// dotted IPv4 without leading zeros and IPv6 with an optional scope, the
// scope restricted by zoneAllowed.
func parsePythonAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || !zoneAllowed(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}

// zoneAllowed reports whether the zone of addr, if any, is acceptable: an
// interface name or index of at most 15 letters, digits, '_', '-' and '.'
// on a link-local unicast, link-local multicast or interface-local
// multicast IPv6 address. Python accepted any zone, but glibc refused
// every non-numeric one when connecting. Go ignores the zone when dialing
// other addresses, and the zone is part of the host-key identity and of
// the known_hosts line, so known_hosts pattern characters or white space
// in it would change what the line matches.
func zoneAllowed(addr netip.Addr) bool {
	zone := addr.Zone()
	if zone == "" {
		return true
	}
	if addr.Is4In6() || !(addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast()) {
		return false
	}
	if len(zone) > 15 {
		return false
	}
	for i := range len(zone) {
		c := zone[i]
		if c != '_' && c != '-' && c != '.' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// pythonAddrString renders addr like str(ipaddress.ip_address(...)):
// RFC 5952 compression, IPv4-mapped addresses with a dotted tail, the
// scope after "%".
func pythonAddrString(addr netip.Addr) string {
	return addr.String()
}

// pyStrip mirrors Python's str.strip() without arguments.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case 0x1c, 0x1d, 0x1e, 0x1f:
			return true
		}
		return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r)
	})
}
