package netpolicy

import "testing"

// With BLOCK_INTERNAL_SSH a NAT64 address (64:ff9b::/96) that embeds a
// private IPv4 address is internal: a NAT64 gateway would reach it.
func TestNAT64EmbeddedPrivateIsInternal(t *testing.T) {
	p, err := New(Config{BlockInternal: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"64:ff9b::a00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::c0a8:101"} {
		if _, err := p.Admit(t.Context(), RoleSSH, s, 22); err == nil {
			t.Errorf("Admit(%s) allowed under BLOCK_INTERNAL_SSH", s)
		}
	}
}
