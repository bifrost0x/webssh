package hosts

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Limits of the probes (collect_identity, collect_reboot_hint).
const (
	identityTimeout   = 4 * time.Second
	rebootHintTimeout = 1500 * time.Millisecond
)

// answerTransient is a probe that failed for another reason (no channel,
// a lost connection). The command may have run, so it counts as sent.
const answerTransient = "transient"

// teeExecutor keeps the first bytes of stdout itself, so that an answer
// cut off by the deadline can still be judged (on_deadline).
type teeExecutor struct {
	conn DetectConn
	max  int
	mu   sync.Mutex
	out  bytes.Buffer
}

func (t *teeExecutor) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return t.conn.Exec(ctx, command, stdin, io.MultiWriter(stdout, t), stderr)
}

func (t *teeExecutor) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if room := t.max - t.out.Len(); room > 0 {
		t.out.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (t *teeExecutor) partial() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return bytes.Clone(t.out.Bytes())
}

// collectIdentity runs IdentityScript and returns the identity, or the
// answer that took its place: answerStalled, answerSilent,
// answerUnsupported or answerTransient.
func collectIdentity(ctx context.Context, conn DetectConn, timeout time.Duration) (Identity, string) {
	cmd, err := remotecmd.Script(IdentityScript, false)
	if err != nil {
		return Identity{}, answerTransient
	}
	cmd.Timeout, cmd.MaxOutput = timeout, MaxIdentityOutput
	tee := &teeExecutor{conn: conn, max: MaxIdentityOutput + 1}
	res, err := remotecmd.Run(ctx, tee, cmd)
	switch {
	case err != nil && fault.CodeOf(err) == fault.Timeout:
		return Identity{}, identityAtDeadline(tee.partial())
	case err != nil:
		return Identity{}, answerTransient
	case res.ExitStatus != 0 || res.Truncated || !utf8.Valid(res.Stdout):
		return Identity{}, answerUnsupported
	}
	id, err := ParseIdentity(string(res.Stdout))
	if err != nil {
		return Identity{}, answerUnsupported
	}
	return id, ""
}

// collectRebootHint runs RebootHintScript; any failure or answer other
// than the one line is an error.
func collectRebootHint(ctx context.Context, conn DetectConn) (bool, error) {
	cmd, err := remotecmd.Script(RebootHintScript, false)
	if err != nil {
		return false, err
	}
	cmd.Timeout, cmd.MaxOutput = rebootHintTimeout, maxRebootHintOutput
	res, err := remotecmd.Run(ctx, conn, cmd)
	if err != nil {
		return false, err
	}
	if res.ExitStatus != 0 || res.Truncated {
		return false, errRebootHint
	}
	return ParseRebootHint(string(res.Stdout))
}
