package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// releasedAuthParts pins the migrations of the owner "auth" that may
// exist in a data directory: their order, and so their version, and a
// digest of their SQL. A released part never moves or changes; a new
// part is appended to authParts and here.
var releasedAuthParts = []struct{ name, sha256 string }{
	{"pending", "a2e2ab173a3ab5fb6e544619ffb74f959d6f6fb67f476745521f5888f9d23bfa"},
	{"factors", "7ae2d539158ddf4a377b3d53e323051ee6e36644a56f59ca32c220192c919fde"},
	{"bootstrap", "b34a7a5a76f397d355b4d9d7db8f14ce3cb69194ac6b60244702490c1cfe040b"},
}

func TestAuthSchemaIsOneOrderedList(t *testing.T) {
	t.Parallel()
	s := Schema()
	if s.Owner != "auth" || len(s.Migrations) != len(authParts) {
		t.Fatalf("owner %q, %d migrations for %d parts", s.Owner, len(s.Migrations), len(authParts))
	}
	if len(authParts) < len(releasedAuthParts) {
		t.Fatalf("a released part was removed: %d of %d", len(authParts), len(releasedAuthParts))
	}
	seen := map[string]bool{}
	for i, p := range authParts {
		if seen[p.name] {
			t.Errorf("part %q twice", p.name)
		}
		seen[p.name] = true
		if m := s.Migrations[i]; m.Version != i+1 || m.SQL != p.sql {
			t.Errorf("migration %d has version %d", i+1, m.Version)
		}
		if i >= len(releasedAuthParts) {
			continue
		}
		sum := sha256.Sum256([]byte(p.sql))
		if want := releasedAuthParts[i]; p.name != want.name || hex.EncodeToString(sum[:]) != want.sha256 {
			t.Errorf("version %d is %q %x, released %q %s", i+1, p.name, sum, want.name, want.sha256)
		}
	}
	// The list applies on an empty store.
	storetest.Open(t, s)
}
