package totp

import (
	"testing"
	"time"
)

// FuzzAcceptedStep: only six ASCII digits (after trimming) can ever match,
// and a match is always one of the three steps around now.
func FuzzAcceptedStep(f *testing.F) {
	f.Add("123456", int64(1111111111))
	f.Add(" 081804\n", int64(1111111111))
	f.Add("８１８０４", int64(59))
	key := []byte("12345678901234567890")
	f.Fuzz(func(t *testing.T, code string, unix int64) {
		now := time.Unix(unix%(1<<40), 0)
		step, ok := acceptedStep(key, code, now)
		if !ok {
			return
		}
		digits := 0
		for _, r := range code {
			if r >= '0' && r <= '9' {
				digits++
			}
		}
		if digits != 6 {
			t.Fatalf("accepted %q", code)
		}
		base := now.Unix() / 30
		if int64(step) < base-1 || int64(step) > base+1 { // #nosec G115 -- test values
			t.Fatalf("step %d outside the window of %d", step, base)
		}
	})
}
