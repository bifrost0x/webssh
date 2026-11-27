package terminal

import "testing"

// R1/R2 I-2: a connection that keeps sending frames that are dropped
// unread is closed with 4002 (an error of HandleBinary); a run of
// dropped frames ends with every frame that is read.
func TestDroppedFramesCloseTheConnection(t *testing.T) {
	r := newTmuxRig(t)
	peer := user(t, 1)
	openTmux(t, r, peer, openReq(1, "r1"))
	for i := range maxDroppedFrames {
		// Out of order on a live channel, then into an unknown channel.
		frame := input(1, 7, "x", false)
		if i%2 == 1 {
			frame = input(99, 1, "x", false)
		}
		if err := r.m.HandleBinary(peer, frame); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	// The expected frame is read and resets the run.
	if err := r.m.HandleBinary(peer, input(1, 1, "a", false)); err != nil {
		t.Fatal(err)
	}
	for i := range maxDroppedFrames {
		if err := r.m.HandleBinary(peer, ack(99, uint64(i))); err != nil {
			t.Fatalf("ack %d: %v", i, err)
		}
	}
	if err := r.m.HandleBinary(peer, input(1, 9, "x", false)); err == nil {
		t.Fatal("dropped frames beyond the limit accepted")
	}
	eventually(t, "the read frame", func() bool { return r.host(t, 0).input() == "a" })
}
