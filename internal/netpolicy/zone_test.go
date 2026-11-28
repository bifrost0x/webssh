package netpolicy

import "testing"

// A zone becomes part of the host-key identity and of the known_hosts
// line, so it may only be an interface name or number on an address that
// has a scope at all. Go ignores the zone when dialing any other address,
// which let ",*" in a zone turn into a known_hosts wildcard.
func TestZonesOnlyOnScopedAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"fe80::1%eth0":       "fe80::1%eth0",
		"[fe80::1%eth0.100]": "fe80::1%eth0.100",
		"fe80::1%2":          "fe80::1%2",
		"FE80::A%wlp2s0":     "fe80::a%wlp2s0",
		"ff02::1%br-lan_1":   "ff02::1%br-lan_1",
		"ff01::1%lo":         "ff01::1%lo",
		"2001:db8::1":        "2001:db8::1",
	} {
		if got, err := CanonicalHost(in); err != nil || got != want {
			t.Errorf("CanonicalHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"::ffff:203.0.113.5%x,*",
		"::ffff:127.0.0.1%x",
		"2001:db8::5%a,*",
		"2001:db8::5%eth0",
		"ff0e::1%eth0",
		"fe80::1%a b",
		"fe80::1%a\nb",
		"fe80::1%*",
		"fe80::1%a|b",
		"fe80::1%a!b",
		"fe80::1%a?b",
		"fe80::1%" + "abcdefghijklmnop",
		"fe80::1%é",
	} {
		if got, err := CanonicalHost(in); err == nil {
			t.Errorf("CanonicalHost(%q) = %q, want a refusal", in, got)
		}
	}
}
