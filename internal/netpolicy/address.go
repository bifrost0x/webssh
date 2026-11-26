package netpolicy

import (
	"net/netip"
	"slices"
)

// Class is the address class of an IP address. The classes are the same
// for every role (ADR 0010); docs/network-policy.md lists which of them
// BLOCK_INTERNAL_SSH=true refuses.
type Class string

// Address classes, from the most specific to public.
const (
	ClassLoopback    Class = "loopback"    // 127.0.0.0/8, ::1
	ClassUnspecified Class = "unspecified" // 0.0.0.0, ::
	ClassLinkLocal   Class = "link-local"  // 169.254.0.0/16, fe80::/10 (cloud metadata services)
	ClassMulticast   Class = "multicast"   // 224.0.0.0/4, ff00::/8
	ClassShared      Class = "shared"      // 100.64.0.0/10: carrier-grade NAT and tailnet nodes
	ClassPrivate     Class = "private"     // RFC 1918, fc00::/7
	ClassReserved    Class = "reserved"    // 240.0.0.0/4 and unassigned IPv6 space
	ClassSpecial     Class = "special"     // other blocks that are not globally reachable
	ClassPublic      Class = "public"
)

// The tables below are the IANA special-purpose registries in the form
// Python's ipaddress module (3.15) applies them. BLOCK_INTERNAL_SSH keeps
// its documented meaning only if Go classifies every address exactly as
// the Python release did; the differential test in policy_python_test.go
// holds the two together.
var (
	v4LinkLocal = netip.MustParsePrefix("169.254.0.0/16")
	v4Loopback  = netip.MustParsePrefix("127.0.0.0/8")
	v4Multicast = netip.MustParsePrefix("224.0.0.0/4")
	v4Shared    = netip.MustParsePrefix("100.64.0.0/10")
	v4Reserved  = netip.MustParsePrefix("240.0.0.0/4")
	v4Private   = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	v4NotGlobal = prefixes(
		"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.0.170/31", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
	)
	v4NotGlobalExceptions = prefixes("192.0.0.9/32", "192.0.0.10/32")

	v6LinkLocal = netip.MustParsePrefix("fe80::/10")
	v6SiteLocal = netip.MustParsePrefix("fec0::/10")
	v6Multicast = netip.MustParsePrefix("ff00::/8")
	v6Private   = netip.MustParsePrefix("fc00::/7")
	v6NotGlobal = prefixes(
		"::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7",
		"fe80::/10",
	)
	v6NotGlobalExceptions = prefixes(
		"2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48",
		"2001:20::/28", "2001:30::/28",
	)
	v6Reserved = prefixes(
		"::/8", "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4",
		"4000::/3", "6000::/3", "8000::/3", "a000::/3", "c000::/3",
		"e000::/4", "f000::/5", "f800::/6", "fe00::/9",
	)
)

// allowlistable are the networks SSH_ALLOWED_INTERNAL_NETWORKS may name.
var allowlistable = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func inAny(addr netip.Addr, list []netip.Prefix) bool {
	return slices.ContainsFunc(list, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// mapped returns the IPv4 address inside an IPv4-mapped IPv6 address. Like
// Python, every class of a mapped address is the class of its IPv4 form.
func mapped(addr netip.Addr) (netip.Addr, bool) {
	if addr.Is4In6() {
		return addr.Unmap(), true
	}
	return addr, false
}

// Classify returns the class of addr. A zone is ignored.
func Classify(addr netip.Addr) Class {
	addr, _ = mapped(addr.WithZone(""))
	switch {
	case !addr.IsValid():
		return ClassSpecial
	case addr.IsUnspecified():
		return ClassUnspecified
	case addr.IsLoopback():
		return ClassLoopback
	case addr.Is4():
		return classifyV4(addr)
	}
	return classifyV6(addr)
}

func classifyV4(addr netip.Addr) Class {
	switch {
	case v4LinkLocal.Contains(addr):
		return ClassLinkLocal
	case v4Multicast.Contains(addr):
		return ClassMulticast
	case v4Shared.Contains(addr):
		return ClassShared
	case inAny(addr, v4Private):
		return ClassPrivate
	case v4Reserved.Contains(addr):
		return ClassReserved
	case !v4Global(addr):
		return ClassSpecial
	}
	return ClassPublic
}

func classifyV6(addr netip.Addr) Class {
	switch {
	case v6LinkLocal.Contains(addr):
		return ClassLinkLocal
	case v6Multicast.Contains(addr):
		return ClassMulticast
	case v6Private.Contains(addr):
		return ClassPrivate
	case v6SiteLocal.Contains(addr) || inAny(addr, v6Reserved):
		return ClassReserved
	case !v6Global(addr):
		return ClassSpecial
	}
	return ClassPublic
}

func v4Global(addr netip.Addr) bool {
	return !v4Shared.Contains(addr) && !(inAny(addr, v4NotGlobal) && !inAny(addr, v4NotGlobalExceptions))
}

func v6Global(addr netip.Addr) bool {
	return !(inAny(addr, v6NotGlobal) && !inAny(addr, v6NotGlobalExceptions))
}

// Internal reports whether BLOCK_INTERNAL_SSH=true refuses addr unless an
// allowance admits it: every class except public. This is the rule of
// app/network_policy.py (_ip_is_internal).
func Internal(addr netip.Addr) bool {
	return Classify(addr) != ClassPublic
}

// allowlisted reports whether one of the allowed internal networks admits
// addr. Loopback, link-local, multicast, unspecified, reserved, site-local
// and IPv4-mapped addresses are never admitted, whatever the list says.
func allowlisted(addr netip.Addr, allowed []netip.Prefix) bool {
	addr = addr.WithZone("")
	if addr.Is4In6() {
		return false
	}
	switch Classify(addr) {
	case ClassLoopback, ClassLinkLocal, ClassMulticast, ClassUnspecified, ClassReserved:
		return false
	}
	return inAny(addr, allowed)
}
