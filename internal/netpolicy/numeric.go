package netpolicy

import (
	"net/netip"
	"strconv"
	"strings"
)

// inetAton parses the numeric IPv4 forms the C library accepts in place of
// a host name (inet_aton, used by getaddrinfo): one to four dot-separated
// parts, each decimal, 0x-hexadecimal or 0-octal, the last part filling the
// remaining bytes ("1681915909", "0x64400005", "100.64.5", "0144.0100.0.5").
// They pass the label rules of a host name, so CanonicalHost keeps them as
// names, but a relay or the system resolver turns them into an address.
// The policy therefore decides on that address and never hands such a name
// to a relay to resolve.
func inetAton(canonical string) (netip.Addr, bool) {
	parts := strings.Split(canonical, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		v, ok := atonPart(part)
		if !ok {
			return netip.Addr{}, false
		}
		values[i] = v
	}
	last := values[len(values)-1]
	if last >= 1<<(8*(5-len(values))) {
		return netip.Addr{}, false
	}
	var out uint64
	for _, v := range values[:len(values)-1] {
		if v > 0xff {
			return netip.Addr{}, false
		}
		out = out<<8 | v
	}
	out = out<<(8*(5-len(values))) | last
	var b [4]byte
	for i := range b {
		b[3-i] = byte(out >> (8 * i)) // #nosec G115 -- masked to one byte
	}
	return netip.AddrFrom4(b), true
}

// atonPart parses one part as strtoul with base 0 does, limited to 32 bits:
// "0x" or "0X" with at least one hexadecimal digit, a leading
// "0" with octal digits, otherwise decimal digits.
func atonPart(part string) (uint64, bool) {
	base, digits := 10, part
	switch {
	case len(part) >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X'):
		base, digits = 16, part[2:]
		if digits == "" {
			return 0, false
		}
	case len(part) > 1 && part[0] == '0':
		base, digits = 8, part[1:]
	case part == "":
		return 0, false
	}
	if digits[0] == '+' || digits[0] == '-' {
		return 0, false
	}
	v, err := strconv.ParseUint(digits, base, 32)
	return v, err == nil
}

// policyAddr returns the address a canonical host stands for without a
// name lookup: an IP literal, or a numeric IPv4 form.
func policyAddr(canonical string) (netip.Addr, bool) {
	if addr, ok := parsePythonAddr(canonical); ok {
		return addr, true
	}
	return inetAton(canonical)
}
