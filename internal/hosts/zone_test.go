package hosts

import "testing"

// New and imported hosts may carry a zone only where netpolicy accepts
// one: an interface name or number on a link-local or interface-local
// address. A stored host with another zone still loads (stored data is
// never dropped); netpolicy refuses it when connecting.
func TestInputHostZones(t *testing.T) {
	for _, h := range []string{"fe80::1%eth0", "fe80::1%2", "ff02::1%br-lan", "2001:db8::1", "host.example", "10.0.0.5"} {
		if !validInputHost(h) {
			t.Errorf("validInputHost(%q) = false", h)
		}
	}
	for _, h := range []string{"::ffff:203.0.113.5%x,*", "2001:db8::5%a,*", "::ffff:1.2.3.4%a b", "::ffff:1.2.3.4%a\nb", "2001:db8::5%eth0", "fe80::1%*"} {
		if validInputHost(h) {
			t.Errorf("validInputHost(%q) = true", h)
		}
		if !validHost(h) {
			t.Errorf("validHost(%q) = false: a stored host would no longer load", h)
		}
	}
}
