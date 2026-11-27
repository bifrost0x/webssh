package hostops

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Limits of one server operation (app/server_operations.py).
const (
	opTimeout   = 15 * time.Second
	opMaxOutput = 64 << 10 // stdout and stderr together
)

// opResult is the answer of a completed command.
type opResult struct {
	Status      string    `json:"status"`
	ExitStatus  int       `json:"exit_status"`
	Output      string    `json:"output"`
	ErrorOutput string    `json:"error_output"`
	Processes   []Process `json:"processes,omitzero"`
}

// busySet allows one command per key at a time (_active, the collector
// locks).
type busySet struct {
	mu   sync.Mutex
	keys map[string]bool
}

func (b *busySet) take(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keys[key] {
		return false
	}
	if b.keys == nil {
		b.keys = map[string]bool{}
	}
	b.keys[key] = true
	return true
}

func (b *busySet) release(key string) {
	b.mu.Lock()
	delete(b.keys, key)
	b.mu.Unlock()
}

// sessionContext ends with ctx, when the session ends or when stop is
// closed (the caller's sign-in was revoked).
func sessionContext(ctx context.Context, done, stop <-chan struct{}) (context.Context, context.CancelFunc) {
	sctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-done:
		case <-stop:
		case <-sctx.Done():
		}
		cancel()
	}()
	return sctx, cancel
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// execute is execute_command: one command on a separate channel of the
// session's connection, never inferring success from terminal output. A
// write whose outcome cannot be known (lost channel, timeout, too much
// output, the session or the sign-in ended meanwhile) answers "unknown",
// so the page never suggests running it again.
func (o *Operations) execute(ctx context.Context, owner int64, sessionID string, want Live, c opCommand, mutating bool, stop <-chan struct{}) (opResult, error) {
	if !o.active.take(sessionID) {
		return opResult{}, opErr("busy")
	}
	defer o.active.release(sessionID)
	unsure := func(code string) error {
		if mutating {
			return opErr("unknown")
		}
		return opErr(code)
	}
	live, ok := o.Sessions.Live(owner, sessionID)
	if !ok || live.Done != want.Done || live.Exec == nil || closed(stop) {
		return opResult{}, opErr("unavailable")
	}
	rctx, cancel := sessionContext(ctx, live.Done, stop)
	defer cancel()
	cmd := remotecmd.Command{Line: c.Line, Stdin: []byte(c.Stdin), Timeout: opTimeout, MaxOutput: opMaxOutput + 1, MaxStderr: opMaxOutput + 1}
	res, err := remotecmd.Run(rctx, live.Exec, cmd)
	switch {
	case err == nil:
	case fault.Is(err, fault.Timeout):
		return opResult{}, unsure("timeout")
	case fault.Is(err, fault.InvalidValue) && !errors.Is(rctx.Err(), context.Canceled):
		// The command line was refused before anything was sent.
		return opResult{}, opErr("unavailable")
	default:
		return opResult{}, unsure("unavailable")
	}
	if len(res.Stdout)+len(res.Stderr) > opMaxOutput {
		return opResult{}, unsure("output_limit")
	}
	status := "failed"
	if res.ExitStatus == 0 {
		status = "completed"
	}
	return opResult{Status: status, ExitStatus: res.ExitStatus, Output: displayText(res.Stdout), ErrorOutput: displayText(res.Stderr)}, nil
}
