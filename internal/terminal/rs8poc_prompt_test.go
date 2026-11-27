package terminal

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

func TestRS8PromptAnswerOnlyByOwnerAndPeer(t *testing.T) {
	r := newPrompts(4)
	q := &prompt{id: "p1", kind: "host_key", peer: 1, owner: 1, answer: make(chan bool, 1)}
	r.add(q)
	for _, c := range []struct {
		peer  uint64
		owner int64
	}{{1, 2}, {2, 1}, {2, 2}} {
		if err := r.resolve(c.peer, c.owner, "p1", "host_key", true); !fault.Is(err, fault.NotFound) {
			t.Fatalf("peer %d owner %d answered: %v", c.peer, c.owner, err)
		}
	}
	if err := r.resolve(1, 1, "p1", "host_key", true); err != nil || !<-q.answer {
		t.Fatalf("owner answer: %v", err)
	}
}
