package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

var owner = Owner{Peer: 3, UserID: 7}

func testAttempt(ev *events) *Attempt {
	if ev == nil {
		ev = newEvents()
	}
	return newAttempt(owner, "req", ev, nil, time.Now())
}

func TestChallengeIsOneShotAndOwned(t *testing.T) {
	ev := newEvents()
	a := testAttempt(ev)
	done := make(chan []string, 1)
	go func() {
		ans, err := a.Challenge(t.Context(), "target", "t", "i", []Prompt{{Label: "Code: "}, {Label: "PIN: ", Echo: true}})
		if err != nil {
			t.Error(err)
		}
		done <- ans
	}()
	got := (<-ev.ch).payload.(protocol.PromptInteractive)
	id := got.PromptID
	if len(id) != 32 || got.RequestID != "req" || !got.Prompts[1].Echo || got.Prompts[0].Echo {
		t.Fatalf("challenge event %+v", got)
	}
	if a.Answer(Owner{Peer: 3, UserID: 8}, id, []string{"1", "2"}) {
		t.Fatal("other user answered")
	}
	if a.Answer(Owner{Peer: 4, UserID: 7}, id, []string{"1", "2"}) {
		t.Fatal("other connection answered")
	}
	if a.Answer(owner, "wrong", []string{"1", "2"}) || a.Answer(owner, id, []string{"1"}) {
		t.Fatal("wrong id or answer count accepted")
	}
	if a.Answer(owner, id, []string{"1", strings.Repeat("x", MaxAnswerBytes)}) {
		t.Fatal("oversized answer accepted")
	}
	if a.Answer(owner, id, []string{"1", "\xff"}) {
		t.Fatal("invalid UTF-8 accepted")
	}
	if !a.Answer(owner, id, []string{"1", "2"}) {
		t.Fatal("valid answer refused")
	}
	if a.Answer(owner, id, []string{"1", "2"}) {
		t.Fatal("replayed answer accepted")
	}
	if got := <-done; strings.Join(got, ",") != "1,2" {
		t.Fatalf("answers %v", got)
	}
}

func TestChallengeLimitsAndCancel(t *testing.T) {
	a := testAttempt(nil)
	if _, err := a.Challenge(t.Context(), "target", "", "", make([]Prompt, MaxPrompts+1)); err == nil {
		t.Fatal("too many prompts")
	}
	if _, err := a.Challenge(t.Context(), "target", strings.Repeat("x", MaxChallengeBytes+1), "", nil); err == nil {
		t.Fatal("oversized challenge")
	}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := a.Challenge(ctx, "target", "", "", []Prompt{{Label: "x"}}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel: %v", err)
	}
	a.mu.Lock()
	pending := a.pending
	a.mu.Unlock()
	if pending != nil {
		t.Fatal("pending challenge left behind")
	}
}

func TestChallengeAfterTheAuthBudget(t *testing.T) {
	a := newAttempt(owner, "req", newEvents(), nil, time.Now().Add(-AuthTimeout))
	if _, err := a.Challenge(t.Context(), "target", "", "", []Prompt{{Label: "x"}}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("challenge after 180 s: %v", err)
	}
}

func TestChallengeToAGonePeer(t *testing.T) {
	ev := newEvents()
	ev.gone = true
	a := testAttempt(ev)
	if _, err := a.Challenge(t.Context(), "target", "", "", []Prompt{{Label: "x"}}); err == nil {
		t.Fatal("challenge without a connection")
	}
}

func TestSecondConcurrentChallengeRefused(t *testing.T) {
	ev := newEvents()
	a := testAttempt(ev)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _, _ = a.Challenge(ctx, "target", "", "", []Prompt{{Label: "x"}}) }()
	<-ev.ch
	if _, err := a.Challenge(ctx, "target", "", "", []Prompt{{Label: "y"}}); err == nil {
		t.Fatal("second pending challenge accepted")
	}
}

func TestInputOnlyDuringSetupAndBounded(t *testing.T) {
	a := testAttempt(nil)
	if a.Input(owner, "y") {
		t.Fatal("input accepted during auth")
	}
	if err := a.StartSetup(); err != nil {
		t.Fatal(err)
	}
	if a.Input(Owner{Peer: 9, UserID: 7}, "y") || a.Input(owner, "") ||
		a.Input(owner, strings.Repeat("a", MaxInputFrame+1)) || a.Input(owner, "\xff") {
		t.Fatal("invalid input accepted")
	}
	total := 0
	for a.Input(owner, strings.Repeat("a", MaxInputFrame)) {
		total += MaxInputFrame
	}
	if total != MaxInputTotal {
		t.Fatalf("accepted %d bytes", total)
	}
	got, err := a.NextInput(t.Context())
	if err != nil || len(got) != MaxInputFrame {
		t.Fatalf("NextInput %d %v", len(got), err)
	}
}

func TestOutputWindowAndAck(t *testing.T) {
	a := testAttempt(nil)
	a.ackTimeout = 100 * time.Millisecond
	for i := range MaxUnackedFrames {
		if err := a.Output(t.Context(), []byte{'a' + byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := a.Output(t.Context(), []byte("x")); !errors.Is(err, ErrCancelled) {
		t.Fatalf("fifth frame without ack: %v", err)
	}
	if time.Since(start) < 90*time.Millisecond {
		t.Fatal("did not wait for an ack")
	}
	if a.Ack(Owner{Peer: 9, UserID: 7}, 1) || a.Ack(owner, 99) {
		t.Fatal("foreign or unknown ack accepted")
	}
	if !a.Ack(owner, 1) || a.Ack(owner, 1) {
		t.Fatal("ack must succeed once")
	}
	if err := a.Output(t.Context(), []byte("x")); err != nil {
		t.Fatalf("after ack: %v", err)
	}
	if err := a.Output(t.Context(), make([]byte, MaxOutputFrame+1)); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestOutputTotalLimit(t *testing.T) {
	ev := &events{ch: make(chan event, 4096)}
	a := testAttempt(ev)
	frame := make([]byte, MaxOutputFrame)
	var err error
	for i := 0; err == nil && i < MaxOutputTotal/MaxOutputFrame+2; i++ {
		err = a.Output(t.Context(), frame)
		a.Ack(owner, a.seq)
		select {
		case <-ev.ch:
		default:
		}
	}
	if !errors.Is(err, errOutputLimit) {
		t.Fatalf("total limit not enforced: %v", err)
	}
}

func TestDecodeCarriesSplitRunes(t *testing.T) {
	a := testAttempt(nil)
	euro := []byte("€") // three bytes
	if got := a.decode(append([]byte("ab"), euro[:1]...)); got != "ab" {
		t.Fatalf("first %q", got)
	}
	if got := a.decode(euro[1:2]); got != "" {
		t.Fatalf("middle %q", got)
	}
	if got := a.decode(append(euro[2:], 'c')); got != "€c" {
		t.Fatalf("last %q", got)
	}
	if got := a.decode([]byte{0xff, 'd'}); got != "�d" {
		t.Fatalf("invalid byte %q", got)
	}
}
