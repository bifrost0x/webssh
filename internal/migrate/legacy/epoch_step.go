package legacy

import (
	"context"
	"errors"
	"strings"

	"github.com/bifrost0x/webssh/internal/store"
)

// epochStep reads entity E18, DATA_DIR/session_epoch, the generation
// Python uses to sign out every browser. Go's revoke-all generation
// starts fresh (D-02); the file stays as it is. A malformed file is STOP:
// Python refuses to start with it too (app/session_epoch.py).
type epochStep struct {
	present bool
}

func (*epochStep) Entity() string { return "E18" }

func (*epochStep) Version() int { return 1 }

func (s *epochStep) Read(_ context.Context, src *Source) error {
	data, err := src.readFile("session_epoch")
	if errors.Is(err, ErrNotFound) {
		return nil // Python creates a new one at its next start
	}
	if err != nil {
		return err
	}
	s.present = true
	if !validEpoch(data) {
		return &StepError{Record: "session_epoch", Err: errors.New("legacy: session_epoch is malformed; the Python release refuses to start with it too")}
	}
	return nil
}

// validEpoch is read_text(encoding='ascii').strip() followed by _valid:
// 64 lower-case hex digits.
func validEpoch(data []byte) bool {
	for _, c := range data {
		if c >= 0x80 {
			return false
		}
	}
	return isLowerHex(strings.Trim(string(data), pythonWhitespace), 64)
}

// pythonWhitespace is what str.strip() removes from ASCII text.
const pythonWhitespace = " \t\n\r\v\f\x1c\x1d\x1e\x1f"

func (*epochStep) Write(context.Context, *store.Tx, Sealer) error { return nil }

func (*epochStep) Verify(context.Context, *store.Tx, Opener) error { return nil }

func (s *epochStep) Report() StepReport {
	r := StepReport{Entity: "E18", Version: 1, Notes: []string{"the session epoch is read only; Go starts a new sign-out generation"}}
	if s.present {
		r.Read, r.Discarded = 1, 1
	}
	return r
}
