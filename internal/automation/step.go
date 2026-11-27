package automation

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// streamBytes is the output kept per stream before cleaning
// (STREAM_OUTPUT_BYTES); more is read and discarded, so a large finite
// output still reaches its exit status.
const streamBytes = 128 << 10

// Executor runs one command on an open connection (*client.Conn).
type Executor = remotecmd.Executor

// capture wraps the executor of a step: it notes when the command took
// its script from stdin (the script reached the host) and keeps the
// first streamBytes of each stream, also when the command is cancelled.
type capture struct {
	on      Executor
	started atomic.Bool
	mu      sync.Mutex
	out     [2][]byte
	over    [2]bool
}

type captureWriter struct {
	c *capture
	i int
}

func (w captureWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	room := streamBytes - len(w.c.out[w.i])
	if len(p) > room {
		w.c.over[w.i] = true
		w.c.out[w.i] = append(w.c.out[w.i], p[:max(room, 0)]...)
	} else {
		w.c.out[w.i] = append(w.c.out[w.i], p...)
	}
	return len(p), nil
}

type startReader struct {
	c *capture
	r io.Reader
}

func (s startReader) Read(p []byte) (int, error) {
	s.c.started.Store(true)
	return s.r.Read(p)
}

func (c *capture) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if stdin != nil {
		stdin = startReader{c, stdin}
	}
	return c.on.Exec(ctx, command, stdin, io.MultiWriter(stdout, captureWriter{c, 0}), io.MultiWriter(stderr, captureWriter{c, 1}))
}

func (c *capture) streams() ([2][]byte, [2]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return [2][]byte{append([]byte(nil), c.out[0]...), append([]byte(nil), c.out[1]...)}, c.over
}

// runStep is execute_step: the step's script on stdin of a fixed command
// line, bounded by the step timeout, with the outcome as the history
// keeps it. cancelled reports a stop of the run; budget is the output
// the run may still keep.
func runStep(ctx context.Context, on Executor, step Step, cancelled func() bool, secrets []string, budget int, now func() time.Time) StepResult {
	started := now()
	c := &capture{on: on}
	result := func(status string, reason *string, exit *int64) StepResult {
		raw, over := c.streams()
		return shapeResult(raw, over, status, reason, exit, secrets, budget, now().Sub(started))
	}
	if cancelled() {
		return result(StatusCancelled, new("cancelled"), nil)
	}
	cmd, err := remotecmd.Script(step.Command, step.Sudo)
	if err != nil {
		return result(StatusFailed, new("dispatch_failed"), nil)
	}
	cmd.Timeout = time.Duration(step.Timeout) * time.Second
	cmd.MaxOutput, cmd.MaxStderr = streamBytes, streamBytes
	res, err := remotecmd.Run(ctx, c, cmd)
	switch {
	case err == nil && res.ExitStatus == 0:
		return result(StatusSucceeded, nil, new(int64(0)))
	case err == nil && res.ExitStatus > 0:
		return result(StatusFailed, new("nonzero_exit"), new(int64(res.ExitStatus)))
	case err == nil:
		return result(StatusUnknown, new("channel_lost"), nil)
	case cancelled() || ctx.Err() != nil:
		if c.started.Load() {
			return result(StatusUnknown, new("cancelled"), nil)
		}
		return result(StatusCancelled, new("cancelled"), nil)
	case fault.Is(err, fault.Timeout):
		return result(StatusUnknown, new("timeout"), nil)
	case errors.Is(err, client.ErrNoExitStatus), c.started.Load():
		return result(StatusUnknown, new("channel_lost"), nil)
	}
	// The script never left WebSSH: the host cannot have run it.
	return result(StatusFailed, new("dispatch_failed"), nil)
}

// shapeResult is result() of execute_step: both streams decoded,
// redacted and cleaned, then cut to the step's share of the budget with
// half reserved for stderr.
func shapeResult(raw [2][]byte, over [2]bool, status string, reason *string, exit *int64, secrets []string, budget int, took time.Duration) StepResult {
	remaining := max(0, min(StepOutputBytes, budget))
	truncated := over[0] || over[1]
	plainSecrets := make([]string, len(secrets))
	for i, s := range secrets {
		plainSecrets[i] = plainOutput(s)
	}
	var encoded [2]string
	for i := range raw {
		incomplete := status == StatusUnknown || over[i]
		decoded, pending := decodeOutput(raw[i], !incomplete)
		truncated = truncated || pending
		value := redactOutput(decoded, secrets, incomplete)
		encoded[i] = redactOutput(plainOutput(value), plainSecrets, incomplete)
	}
	stderrBudget := min(len(encoded[1]), remaining/2)
	stdoutBudget := min(len(encoded[0]), remaining-stderrBudget)
	stderrBudget = remaining - stdoutBudget
	kept := [2]string{cutUTF8(encoded[0], stdoutBudget), cutUTF8(encoded[1], stderrBudget)}
	truncated = truncated || len(kept[0]) < len(encoded[0]) || len(kept[1]) < len(encoded[1])
	return StepResult{Status: status, Reason: reason, ExitCode: exit, Duration: durationText(took.Seconds()),
		Detailed: true, Stdout: kept[0], Stderr: kept[1], Truncated: truncated}
}

// cutUTF8 is value[:n].decode('utf-8', errors='ignore') of the encoded
// text: a character cut in half is dropped.
func cutUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	n = max(n, 0)
	for n > 0 && n < len(s) && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xc0 != 0x80 }
