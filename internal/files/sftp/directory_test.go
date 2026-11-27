package sftp

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

type pyDirectory struct {
	Directory []struct {
		B64    string `json:"b64"`
		Result *struct {
			Path           string `json:"path"`
			ShellReady     bool   `json:"shell_ready"`
			ShellID        string `json:"shell_id"`
			Shell          string `json:"shell"`
			BracketedPaste *bool  `json:"bracketed_paste"`
			Prompt         *struct {
				Generation int64  `json:"generation"`
				Phase      string `json:"phase"`
			} `json:"prompt"`
		} `json:"result"`
	} `json:"directory"`
	Probe []struct {
		Tmux    string `json:"tmux"`
		Command string `json:"command"`
	} `json:"probe"`
}

func TestPythonDirectoryRules(t *testing.T) {
	var v struct {
		Vectors pyDirectory `json:"vectors"`
	}
	loadPythonInto(t, &v)
	if len(v.Vectors.Directory) == 0 || len(v.Vectors.Probe) == 0 {
		t.Fatal("no vectors")
	}
	for i, c := range v.Vectors.Directory {
		d, err := ParseDirectory(b64(t, c.B64))
		if c.Result == nil {
			if err == nil {
				t.Errorf("directory %d: Go accepts %+v, Python refused", i, d)
			}
			continue
		}
		r := c.Result
		ok := err == nil && d.Path == r.Path && d.ShellReady == r.ShellReady && d.ShellID == r.ShellID && d.Shell == r.Shell &&
			(d.BracketedPaste == nil) == (r.BracketedPaste == nil) && (d.BracketedPaste == nil || *d.BracketedPaste == *r.BracketedPaste) &&
			(d.Prompt == nil) == (r.Prompt == nil) && (d.Prompt == nil || d.Prompt.Generation == r.Prompt.Generation && d.Prompt.Phase == r.Prompt.Phase)
		if !ok {
			t.Errorf("directory %d: Go %+v %v, Python %+v", i, d, err, r)
		}
	}
	for _, c := range v.Vectors.Probe {
		if got := DirectoryCommand(c.Tmux); got != c.Command {
			t.Errorf("probe for tmux %q differs:\n%s\n---\n%s", c.Tmux, got, c.Command)
		}
	}
}

type execFunc func(cmd string, out io.Writer) (int, error)

func (f execFunc) Exec(_ context.Context, cmd string, _ io.Reader, out, _ io.Writer) (int, error) {
	return f(cmd, out)
}

func TestCollectDirectoryFailsClosed(t *testing.T) {
	answer := "webssh-directory\x0042\x001\x00bash\x00/srv/www\x00"
	d, err := CollectDirectory(t.Context(), execFunc(func(cmd string, out io.Writer) (int, error) {
		if !strings.HasPrefix(cmd, "exec sh -c ") {
			t.Fatalf("command %q", cmd)
		}
		_, _ = io.WriteString(out, answer)
		return 0, nil
	}), "")
	if err != nil || d.Path != "/srv/www" || !d.ShellReady {
		t.Fatalf("%+v %v", d, err)
	}
	cases := []struct {
		f    execFunc
		want error
	}{
		{func(_ string, out io.Writer) (int, error) { return 1, nil }, ErrDirectoryUnsupported},
		{func(_ string, out io.Writer) (int, error) {
			_, _ = out.Write(bytes.Repeat([]byte("x"), 9000))
			return 0, nil
		}, ErrDirectoryUnsupported},
		{func(_ string, out io.Writer) (int, error) { _, _ = io.WriteString(out, "garbage"); return 0, nil }, ErrDirectoryUnsupported},
		{func(string, io.Writer) (int, error) { return -1, io.ErrUnexpectedEOF }, ErrDirectoryUnavailable},
	}
	for i, c := range cases {
		if _, err := CollectDirectory(t.Context(), c.f, "webssh-x"); err != c.want {
			t.Errorf("case %d: %v, want %v", i, err, c.want)
		}
	}
}

func FuzzParseDirectory(f *testing.F) {
	f.Add([]byte("webssh-directory\x0042\x001\x00bash\x00/srv\x001\x0042:3:p\x00"))
	f.Add([]byte("webssh-directory\x0042\x000\x00sh\x00/\x00"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		d, err := ParseDirectory(raw)
		if err != nil {
			return
		}
		if !strings.HasPrefix(d.Path, "/") || len(d.Path) > 4096 || strings.ContainsAny(d.Path, "\x00\n\r") {
			t.Fatalf("accepted %q", d.Path)
		}
	})
}
