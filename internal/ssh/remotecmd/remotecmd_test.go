package remotecmd_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// fakeExec records the command and answers like a remote program.
type fakeExec struct {
	line   string
	stdin  []byte
	output []byte
	stderr []byte
	status int
	err    error
	hang   bool
}

func (f *fakeExec) Exec(ctx context.Context, line string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	f.line = line
	if stdin != nil {
		f.stdin, _ = io.ReadAll(stdin)
	}
	if f.hang {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	// Write in small pieces, as a channel delivers data.
	for chunk := range slicesChunk(f.output, 7) {
		if n, err := stdout.Write(chunk); n != len(chunk) || err != nil {
			return -1, errors.New("writer refused data")
		}
	}
	_, _ = stderr.Write(f.stderr)
	return f.status, f.err
}

func slicesChunk(b []byte, n int) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		for len(b) > 0 {
			k := min(n, len(b))
			if !yield(b[:k]) {
				return
			}
			b = b[k:]
		}
	}
}

func TestRunPassesLineStdinAndResult(t *testing.T) {
	f := &fakeExec{output: []byte("out"), stderr: []byte("err"), status: 2}
	r, err := remotecmd.Run(t.Context(), f, remotecmd.Command{Line: "tmux has-session -t '=x'", Stdin: []byte("data")})
	if err != nil {
		t.Fatal(err)
	}
	if f.line != "tmux has-session -t '=x'" || string(f.stdin) != "data" {
		t.Fatalf("sent %q %q", f.line, f.stdin)
	}
	if r.ExitStatus != 2 || string(r.Stdout) != "out" || string(r.Stderr) != "err" || r.Truncated {
		t.Fatalf("result %+v", r)
	}
}

func TestRunCapsOutputAndDrainsTheRest(t *testing.T) {
	f := &fakeExec{output: bytes.Repeat([]byte("a"), 100), stderr: bytes.Repeat([]byte("e"), 10000)}
	r, err := remotecmd.Run(t.Context(), f, remotecmd.Command{Line: "x", MaxOutput: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Stdout) != 10 || !r.Truncated || len(r.Stderr) != 4096 {
		t.Fatalf("kept %d/%d truncated=%v", len(r.Stdout), len(r.Stderr), r.Truncated)
	}
	r, _ = remotecmd.Run(t.Context(), &fakeExec{output: []byte("0123456789")}, remotecmd.Command{Line: "x", MaxOutput: 10})
	if r.Truncated || len(r.Stdout) != 10 {
		t.Fatalf("exact fit reported as truncated: %+v", r)
	}
}

func TestRunTimesOut(t *testing.T) {
	start := time.Now()
	_, err := remotecmd.Run(t.Context(), &fakeExec{hang: true}, remotecmd.Command{Line: "x", Timeout: 50 * time.Millisecond})
	if fault.CodeOf(err) != fault.Timeout || time.Since(start) > 2*time.Second {
		t.Fatalf("timeout: %v", err)
	}
	// A cancelled caller is not reported as a timeout.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = remotecmd.Run(ctx, &fakeExec{hang: true}, remotecmd.Command{Line: "x"})
	if fault.CodeOf(err) == fault.Timeout || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestRunRefusesInvalidCommands(t *testing.T) {
	bad := []remotecmd.Command{
		{},
		{Line: "a\nb"},
		{Line: "a\rb"},
		{Line: "a\x00b"},
		{Line: "a\x7fb"},
		{Line: strings.Repeat("x", remotecmd.MaxLine+1)},
		{Line: "x", Stdin: make([]byte, remotecmd.MaxStdin+1)},
		{Line: "x", Timeout: -1},
		{Line: "x", MaxOutput: remotecmd.MaxOutput + 1},
	}
	for i, c := range bad {
		f := &fakeExec{}
		if _, err := remotecmd.Run(t.Context(), f, c); fault.CodeOf(err) != fault.InvalidValue || f.line != "" {
			t.Fatalf("case %d ran: %v", i, err)
		}
	}
}

func TestWord(t *testing.T) {
	for _, ok := range []string{"webssh_u_h_22_0a1b2c3d", "=name:", "a-b.c,d/e@f%g+h"} {
		if q, err := remotecmd.Word(ok); err != nil || q != "'"+ok+"'" {
			t.Fatalf("%q: %q %v", ok, q, err)
		}
	}
	for _, bad := range []string{"", "a b", "a'b", `a\b`, "a;b", "a$b", "a`b", "a\nb", "a!b", "ä", "a\"b", "a*b", "a|b", strings.Repeat("a", 257)} {
		if _, err := remotecmd.Word(bad); fault.CodeOf(err) != fault.InvalidValue {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func FuzzWord(f *testing.F) {
	f.Add("webssh_a_b_22_deadbeef")
	f.Add("a'b")
	f.Fuzz(func(t *testing.T, s string) {
		q, err := remotecmd.Word(s)
		if err != nil {
			return
		}
		inner := q[1 : len(q)-1]
		if inner != s || strings.ContainsAny(inner, "'\\\"$`!;&|<>(){}[]*?~# \t\r\n") {
			t.Fatalf("unsafe word %q", q)
		}
	})
}

// partialExec writes output, then waits for the end of ctx.
type partialExec struct{ out string }

func (p partialExec) Exec(ctx context.Context, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
	_, _ = stdout.Write([]byte(p.out))
	<-ctx.Done()
	return -1, ctx.Err()
}

func TestRunKeepsTheOutputOfATimeout(t *testing.T) {
	r, err := remotecmd.Run(t.Context(), partialExec{"cpu=1 2 3 4\n"}, remotecmd.Command{Line: "x", Timeout: 30 * time.Millisecond})
	if fault.CodeOf(err) != fault.Timeout || string(r.Stdout) != "cpu=1 2 3 4\n" || r.ExitStatus != -1 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestRunMaxStderr(t *testing.T) {
	f := &fakeExec{stderr: bytes.Repeat([]byte("e"), 10000)}
	r, err := remotecmd.Run(t.Context(), f, remotecmd.Command{Line: "x", MaxStderr: 9000})
	if err != nil || len(r.Stderr) != 9000 || !r.StderrTruncated {
		t.Fatalf("%d %v %v", len(r.Stderr), r.StderrTruncated, err)
	}
	for _, bad := range []int{-1, remotecmd.MaxOutput + 1} {
		if _, err := remotecmd.Run(t.Context(), &fakeExec{}, remotecmd.Command{Line: "x", MaxStderr: bad}); fault.CodeOf(err) != fault.InvalidValue {
			t.Fatalf("MaxStderr %d: %v", bad, err)
		}
	}
}

func TestInert(t *testing.T) {
	for _, ok := range []string{"nginx.service", "getty@tty1.service", "a:b", "x-y_z"} {
		if !remotecmd.Inert(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "a b", "a;b", "a$b", "a'b", "a\nb", "ä"} {
		if remotecmd.Inert(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
