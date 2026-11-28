package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Texts of a gateway round go through the same cleaning as those of an
// ordinary keyboard-interactive round: no bidi overrides, invisible format
// characters or control characters reach the dialog. Spaces stay, so a
// label keeps the form the Python release showed.
func TestChallengeCleansRemoteTexts(t *testing.T) {
	ev := newEvents()
	a := newAttempt(owner, "req", ev, nil, time.Now())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.Challenge(ctx, "target", "Warp\u202egate\x1b[2J", "line one\r\nline\u200b two\x07",
			[]Prompt{{Label: "Co\u2066de: \xff"}})
	}()
	p := (<-ev.ch).payload.(protocol.PromptInteractive)
	cancel()
	<-done
	if p.Title != "Warpgate[2J" || p.Instructions != "line one\nline two" {
		t.Errorf("title %q, instructions %q", p.Title, p.Instructions)
	}
	if l := p.Prompts[0].Label; l != "Code: \ufffd" {
		t.Errorf("label %q", l)
	}
}
