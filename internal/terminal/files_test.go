package terminal

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

// A session's connection is given only to its owner, and only when its
// shell runs on a connection of the dialer.
func TestFileSessionIsOwnedAndNeedsAConnection(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	res := open(t, m, user(t, 1), 1)
	for _, c := range []struct {
		owner int64
		id    string
	}{{2, res.SessionID}, {1, "missing"}, {1, res.SessionID}} {
		// The fake shell has no SSH connection of its own.
		if _, err := m.FileSession(c.owner, c.id); !fault.Is(err, fault.SourceUnavailable) {
			t.Fatalf("owner %d session %q: %v", c.owner, c.id, err)
		}
	}
}
