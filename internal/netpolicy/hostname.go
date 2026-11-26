package netpolicy

import (
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Host name refusals. The texts are safe to show.
var (
	errHostRequired = fault.New(fault.InvalidValue, "Host is required.")
	errHostFormat   = fault.New(fault.InvalidValue, "Invalid host format.")
	errHostIDNA     = fault.New(fault.InvalidValue, "Internationalized host names are not supported in this preview; use the xn-- form.")
)

// CanonicalHost returns the form used for policy decisions and host-key
// identity, exactly as app/network_policy.py canonicalize_hostname: the
// value stripped, one pair of brackets and all trailing dots removed, an
// IP literal in Python's string form, a name in lower case with RFC 1123
// labels.
//
// Python converts non-ASCII names with the IDNA 2003 codec. Go has no
// bit-identical implementation, and host keys are stored under the
// converted name, so such names are refused instead of being guessed.
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
	for i := range len(value) {
		if value[i] >= utf8.RuneSelf {
			return "", errHostIDNA
		}
	}
	// The ASCII path of Python's IDNA codec: every label but the last must
	// have 1 to 63 bytes, the last fewer than 64.
	labels := strings.Split(value, ".")
	for i, label := range labels {
		if len(label) >= 64 || (len(label) == 0 && i < len(labels)-1) {
			return "", errHostFormat
		}
	}
	canonical := strings.ToLower(value)
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
// dotted IPv4 without leading zeros and IPv6 with an optional scope.
func parsePythonAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	if zone := addr.Zone(); zone != "" && strings.Contains(zone, "%") {
		return netip.Addr{}, false
	}
	return addr, true
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
