package hostkey

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Record writes the host name into a known_hosts line. A name that the
// parser would read as several names, a pattern, a comment or a marker is
// refused, whatever the caller checked before: one such line would make
// a key trusted for other hosts, global pins included, or make the file
// unreadable.
func TestRecordRefusesNamesThatAreNotOneHost(t *testing.T) {
	s, db := newStore(t)
	ctx := t.Context()
	pinned, attacker := newKey(t), newKey(t)
	importRaw(t, db, ScopeGlobal, 0, FormatLine("prod.example", pinned))
	for _, host := range []string{
		"::ffff:203.0.113.5%x,*", "*", "a,b", "h?", "!h", "a|b", "#h", "@cert-authority",
		"a b", "a\tb", "a\nb", "a\rb", "a\x00b", "a\x7fb", "",
	} {
		for _, port := range []int{22, 2222} {
			err := s.Record(ctx, 1, host, port, attacker)
			if fault.CodeOf(err) != fault.InvalidValue {
				t.Errorf("Record(%q, %d) = %v, want an invalid value", host, port, err)
			}
		}
	}
	for _, host := range []string{"prod.example", "github.com", "10.0.0.5"} {
		if ok, _ := s.Known(ctx, 1, host, 22, attacker); ok {
			t.Errorf("attacker key trusted for %s", host)
		}
	}
	if err := s.Record(ctx, 1, "fe80::1%eth0", 2222, attacker); err != nil {
		t.Errorf("scoped literal: %v", err)
	}
	if ok, err := s.Known(ctx, 1, "fe80::1%eth0", 2222, attacker); !ok || err != nil {
		t.Errorf("scoped literal not trusted after Record: %v, %v", ok, err)
	}
}
