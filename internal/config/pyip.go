package config

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// pyAddr is an address parsed like Python's ipaddress.ip_address. Python
// keeps an IPv6 scope ("%eth0") as part of the address.
type pyAddr struct {
	addr netip.Addr // without zone
	zone string
	is4  bool
}

func (a pyAddr) String() string {
	if a.zone != "" {
		return a.addr.String() + "%" + a.zone
	}
	return a.addr.String()
}

var errPyIP = errors.New("invalid IP address")

// pyIPAddress is ipaddress.ip_address(s) for a str.
func pyIPAddress(s string) (pyAddr, error) {
	if v4, err := pyIPv4(s); err == nil {
		return pyAddr{addr: netip.AddrFrom4(v4), is4: true}, nil
	}
	v6, zone, err := pyIPv6(s)
	if err != nil {
		return pyAddr{}, err
	}
	return pyAddr{addr: netip.AddrFrom16(v6), zone: zone}, nil
}

func pyIPv4(s string) ([4]byte, error) {
	var out [4]byte
	if s == "" || strings.Contains(s, "/") {
		return out, errPyIP
	}
	octets := strings.Split(s, ".")
	if len(octets) != 4 {
		return out, errPyIP
	}
	for i, o := range octets {
		if !isASCIIDigits(o) || len(o) > 3 || len(o) > 1 && o[0] == '0' {
			return out, errPyIP
		}
		v := 0
		for j := range len(o) {
			v = v*10 + int(o[j]-'0')
		}
		if v > 255 {
			return out, errPyIP
		}
		out[i] = byte(v)
	}
	return out, nil
}

func pyIPv6(s string) (addr [16]byte, zone string, err error) {
	if strings.Contains(s, "/") {
		return addr, "", errPyIP
	}
	s, zone, found := strings.Cut(s, "%")
	if found && (zone == "" || strings.Contains(zone, "%")) {
		return addr, "", errPyIP
	}
	if s == "" || runeLen(s) > 45 {
		return addr, "", errPyIP
	}
	const hextets = 8
	parts := strings.SplitN(s, ":", hextets+2)
	if len(parts) < 3 {
		return addr, "", errPyIP
	}
	if last := parts[len(parts)-1]; strings.Contains(last, ".") {
		v4, err := pyIPv4(last)
		if err != nil {
			return addr, "", errPyIP
		}
		parts = append(parts[:len(parts)-1], hex16(uint16(v4[0])<<8|uint16(v4[1])), hex16(uint16(v4[2])<<8|uint16(v4[3])))
	}
	if len(parts) > hextets+1 {
		return addr, "", errPyIP
	}
	skip := -1
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			if skip >= 0 {
				return addr, "", errPyIP
			}
			skip = i
		}
	}
	var hi, lo int
	if skip >= 0 {
		hi, lo = skip, len(parts)-skip-1
		if parts[0] == "" {
			if hi--; hi != 0 {
				return addr, "", errPyIP
			}
		}
		if parts[len(parts)-1] == "" {
			if lo--; lo != 0 {
				return addr, "", errPyIP
			}
		}
		if hextets-(hi+lo) < 1 {
			return addr, "", errPyIP
		}
	} else {
		if len(parts) != hextets || parts[0] == "" || parts[len(parts)-1] == "" {
			return addr, "", errPyIP
		}
		hi = len(parts)
	}
	words := make([]uint16, 0, hextets)
	for i := range hi {
		w, ok := parseHextet(parts[i])
		if !ok {
			return addr, "", errPyIP
		}
		words = append(words, w)
	}
	for len(words) < hextets-lo {
		words = append(words, 0)
	}
	for i := len(parts) - lo; i < len(parts); i++ {
		w, ok := parseHextet(parts[i])
		if !ok {
			return addr, "", errPyIP
		}
		words = append(words, w)
	}
	for i, w := range words {
		binary.BigEndian.PutUint16(addr[2*i:], w)
	}
	return addr, zone, nil
}

func parseHextet(s string) (uint16, bool) {
	if s == "" || len(s) > 4 {
		return 0, false
	}
	var v uint16
	for i := range len(s) {
		c := s[i]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | uint16(d)
	}
	return v, true
}

func hex16(v uint16) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v&0xf]
		v >>= 4
	}
	return string(b[i:])
}

// pyNetwork is a network parsed like ipaddress.ip_network(s, strict=True).
type pyNetwork struct {
	addr pyAddr // network address, with the zone Python keeps
	bits int
}

func (n pyNetwork) String() string {
	return n.addr.String() + "/" + strconv.Itoa(n.bits)
}

// prefix returns the network for address matching. Python compares the
// integers when it tests membership, so the zone has no part in it.
func (n pyNetwork) prefix() netip.Prefix {
	return netip.PrefixFrom(n.addr.addr, n.bits)
}

// equal is Python's network equality: version, network address including
// the zone, and netmask.
func (n pyNetwork) equal(o pyNetwork) bool {
	return n.addr.addr == o.addr.addr && n.addr.zone == o.addr.zone && n.bits == o.bits
}

// pyIPNetwork is ipaddress.ip_network(s, strict=True) for a str.
func pyIPNetwork(s string) (pyNetwork, error) {
	if n, err := pyIPNetworkV(s, true); err == nil {
		return n, nil
	}
	return pyIPNetworkV(s, false)
}

func pyIPNetworkV(s string, v4 bool) (pyNetwork, error) {
	parts := strings.Split(s, "/")
	if len(parts) > 2 {
		return pyNetwork{}, errPyIP
	}
	var a pyAddr
	maxBits := 128
	if v4 {
		b, err := pyIPv4(parts[0])
		if err != nil {
			return pyNetwork{}, err
		}
		a, maxBits = pyAddr{addr: netip.AddrFrom4(b), is4: true}, 32
	} else {
		b, zone, err := pyIPv6(parts[0])
		if err != nil {
			return pyNetwork{}, err
		}
		a = pyAddr{addr: netip.AddrFrom16(b), zone: zone}
	}
	bits := maxBits
	if len(parts) == 2 {
		var ok bool
		if bits, ok = prefixLength(parts[1], maxBits, v4); !ok {
			return pyNetwork{}, errPyIP
		}
	}
	p := netip.PrefixFrom(a.addr, bits)
	if p.Masked().Addr() != a.addr {
		return pyNetwork{}, errPyIP // host bits set
	}
	return pyNetwork{addr: a, bits: bits}, nil
}

// prefixLength accepts a decimal prefix length (leading zeros allowed) and,
// for IPv4 only, a dotted netmask or host mask.
func prefixLength(s string, maxBits int, v4 bool) (int, bool) {
	if isASCIIDigits(s) {
		v, _ := pyInt(s)
		if v.IsInt64() && v.Int64() <= int64(maxBits) {
			return int(v.Int64()), true
		}
		if !v4 {
			return 0, false
		}
	} else if !v4 {
		return 0, false
	}
	b, err := pyIPv4(s)
	if err != nil {
		return 0, false
	}
	m := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if n, ok := maskBits(m); ok {
		return n, true
	}
	return maskBits(^m)
}

// maskBits returns the prefix length of a contiguous netmask (ones, then
// zeros).
func maskBits(m uint32) (int, bool) {
	n := 0
	for n < 32 && m&(1<<(31-n)) != 0 {
		n++
	}
	if n < 32 && m<<n != 0 {
		return 0, false
	}
	return n, true
}

// subnetOf is Python's a.subnet_of(b) for networks of the same version.
// Python orders addresses by integer and treats them as equal only with
// the same zone, which this reproduces.
func (n pyNetwork) subnetOf(b pyNetwork) bool {
	if n.addr.is4 != b.addr.is4 {
		return false
	}
	lowOK := b.addr.addr.Less(n.addr.addr) || b.addr.addr == n.addr.addr && b.addr.zone == n.addr.zone
	return lowOK && n.bits >= b.bits && b.prefix().Contains(n.addr.addr)
}
