package hostops

import (
	"bytes"
	"encoding/json/jsontext"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits of one scan (discovery_routes.py).
const (
	MaxScanAddresses = 256
	MaxScanPorts     = 3
	maxNetworkInput  = 64
)

// scanInputError selects a fixed message, never the parser's text.
type scanInputError string

const (
	errScanNetwork     scanInputError = "network"
	errScanNetworkSize scanInputError = "network_size"
	errScanPorts       scanInputError = "ports"
)

func (e scanInputError) Error() string { return scanInputMessages[e] }

var scanInputMessages = map[scanInputError]string{
	errScanNetwork:     "Enter a network such as 192.168.1.0/24.",
	errScanNetworkSize: "Choose a range of at most 256 addresses (for example a /24).",
	errScanPorts:       "Choose up to three ports between 1 and 65535.",
}

// parseNetwork is parse_network with ip_network(strict=False): an address,
// optionally with a prefix length, or for IPv4 a netmask or host mask;
// host bits are cleared. It returns the canonical network and the
// addresses to probe: for IPv4 ranges larger than /31 the hosts without
// network and broadcast address, otherwise every address. Unlike the
// Python release a scoped IPv6 address (fe80::1%eth0) is refused: the
// scope was dropped before probing, so such a scan could not reach the
// link the user named.
func parseNetwork(value string) (netip.Prefix, []netip.Addr, error) {
	if utf8.RuneCountInString(value) > maxNetworkInput {
		return netip.Prefix{}, nil, errScanNetwork
	}
	value = pyStrip(value)
	if value == "" {
		return netip.Prefix{}, nil, errScanNetwork
	}
	addrText, maskText, hasMask := strings.Cut(value, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, nil, errScanNetwork
	}
	bits := addr.BitLen()
	if hasMask {
		if bits, err = maskBits(addr, maskText); err != nil {
			return netip.Prefix{}, nil, err
		}
	}
	prefix := netip.PrefixFrom(addr, bits).Masked()
	if hostBits := addr.BitLen() - bits; hostBits > 8 {
		return netip.Prefix{}, nil, errScanNetworkSize
	}
	var all []netip.Addr
	for a := prefix.Addr(); prefix.Contains(a); a = a.Next() {
		all = append(all, a)
		if !a.Next().IsValid() {
			break
		}
	}
	if addr.Is4() && bits < 31 {
		all = all[1 : len(all)-1]
	}
	return prefix, all, nil
}

// maskBits reads a prefix length (ASCII digits, leading zeros allowed) or,
// for IPv4, a netmask or host mask in dotted form.
func maskBits(addr netip.Addr, text string) (int, error) {
	if text != "" && strings.Trim(text, "0123456789") == "" {
		n, err := strconv.Atoi(text)
		if err != nil || n > addr.BitLen() {
			return 0, errScanNetwork
		}
		return n, nil
	}
	if !addr.Is4() {
		return 0, errScanNetwork
	}
	mask, err := netip.ParseAddr(text)
	if err != nil || !mask.Is4() {
		return 0, errScanNetwork
	}
	v := mask.As4()
	n := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	// A netmask is ones then zeros; a host mask zeros then ones.
	for _, m := range []uint32{n, ^n} {
		if ones := leadingOnes(m); m == ^uint32(0)<<(32-ones) {
			return ones, nil
		}
	}
	return 0, errScanNetwork
}

func leadingOnes(m uint32) int {
	n := 0
	for m&(1<<31) != 0 {
		n++
		m <<= 1
	}
	return n
}

// parsePorts is parse_ports: absent or null is [22]; otherwise one to
// three JSON integers between 1 and 65535, deduplicated and sorted.
func parsePorts(raw jsontext.Value) ([]int, error) {
	if len(raw) == 0 || raw.Kind() == 'n' {
		return []int{22}, nil
	}
	if raw.Kind() != '[' {
		return nil, errScanPorts
	}
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.ReadToken(); err != nil {
		return nil, errScanPorts
	}
	var ports []int
	for dec.PeekKind() != ']' {
		v, err := dec.ReadValue()
		if err != nil || v.Kind() != '0' || len(ports) == MaxScanPorts {
			return nil, errScanPorts
		}
		// type(port) is int: no fraction, no exponent.
		n, err := strconv.Atoi(string(v))
		if err != nil || n < 1 || n > 65535 {
			return nil, errScanPorts
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, errScanPorts
	}
	slices.Sort(ports)
	return slices.Compact(ports), nil
}
