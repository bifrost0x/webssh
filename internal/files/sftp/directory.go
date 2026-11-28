package sftp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// The terminal directory probe (C-SFTP-10, app/session_directory.py):
// the file browser follows the directory of the interactive shell. An exec
// channel on the same SSH connection reads /proc/<pid>/cwd of the shell
// without writing to its PTY. Linux with OpenSSH only; ambiguous answers
// fail closed. tmux names its active pane instead.

const directoryProbe = `
LC_ALL=C; export LC_ALL
command -v ps >/dev/null && command -v readlink >/dev/null || exit 1
__DIRECTORY_SELECT__
case "$directory_pid" in ''|*[!0-9]*) exit 1;; esac
# Follow the foreground process group, including a nested interactive shell.
directory_fg=$(ps -o tpgid= -p "$directory_pid" | tr -d ' ')
case "$directory_fg" in ''|*[!0-9]*) exit 1;; esac
directory_shell=$(ps -o comm= -p "$directory_fg")
directory_ready=0
case "$directory_shell" in bash|zsh|fish|sh|dash|ksh) directory_ready=1;; esac
if [ "$directory_ready" = 1 ]; then
  directory_pid=$directory_fg
else
  # A foreground command can belong to a nested shell. Keep that shell's
  # directory rather than falling back to the outer login shell.
  directory_walk=$directory_fg
  directory_found=0
  for directory_step in 1 2 3 4 5 6 7 8; do
    directory_walk=$(ps -o ppid= -p "$directory_walk" | tr -d ' ')
    case "$directory_walk" in ''|*[!0-9]*) exit 1;; esac
    directory_name=$(ps -o comm= -p "$directory_walk")
    case "$directory_name" in
      bash|zsh|fish|sh|dash|ksh)
        directory_pid=$directory_walk
        directory_shell=$directory_name
        directory_found=1
        break
        ;;
    esac
    [ "$directory_walk" != 1 ] || exit 1
  done
  [ "$directory_found" = 1 ] || exit 1
fi
directory_path=$(readlink -n "/proc/$directory_pid/cwd" && printf '.') || exit 1
directory_path=${directory_path%.}
printf 'webssh-directory\000%s\000%s\000%s\000%s\000' "$directory_pid" "$directory_ready" "$directory_shell" "$directory_path"
if [ "${directory_marker+x}" = x ]; then
  printf '%s\000%s\000' "${directory_paste-}" "$directory_marker"
elif [ "${directory_paste+x}" = x ]; then printf '%s\000' "$directory_paste"; fi
`

const directShell = `
directory_parent=$(ps -o ppid= -p "$$" | tr -d ' ')
directory_pid=$(ps -o pid=,tty= --ppid "$directory_parent" | awk '$2 != "?" {print $1}')
`

// tmuxShell selects the active pane of the persistent tmux session
// __TMUX_TARGET__ (tests/integration/tmux_sync_driver.py reads it too).
const tmuxShell = `directory_pane=$(tmux display-message -p -t __TMUX_TARGET__ '#{?pane_in_mode,0,#{?alternate_on,0,#{pane_pid}}}:#{bracket_paste_flag}:#{@webssh_sync_v1}') || exit 1
directory_pid=${directory_pane%%:*}
directory_rest=${directory_pane#*:}
directory_marker=${directory_rest#*:}
directory_paste=${directory_rest%%:*}
case "$directory_paste" in 0|1) ;; "") unset directory_paste;; *) exit 1;; esac
[ "$directory_pid" != 0 ] || exit 1`

// DirectoryCommand returns the probe for a session; tmuxSession is the
// name of the persistent tmux session, "" for a plain shell.
func DirectoryCommand(tmuxSession string) string {
	sel := directShell
	if tmuxSession != "" {
		sel = strings.Replace(tmuxShell, "__TMUX_TARGET__", remotecmd.Quote("="+tmuxSession+":"), 1)
	}
	return "exec sh -c " + remotecmd.Quote(strings.Replace(directoryProbe, "__DIRECTORY_SELECT__", sel, 1))
}

// Directory is the answer of the probe.
type Directory struct {
	Path       string
	ShellReady bool
	ShellID    string
	Shell      string
	// BracketedPaste is set when tmux reported it.
	BracketedPaste *bool
	// Prompt is the prompt marker of a bash inside tmux, if any.
	Prompt *Prompt
}

// Prompt is the marker the bash prompt hook of WebSSH leaves in tmux.
type Prompt struct {
	Generation int64
	Phase      string // p, c or b
}

var (
	errDirectory  = errors.New("unsupported directory answer")
	promptPattern = regexp.MustCompile(`^([0-9]+):([1-9][0-9]{0,14}):([pcb])$`)
	directShells  = []string{"bash", "zsh", "fish", "sh", "dash", "ksh"}
)

// ParseDirectory reads the probe's answer (parse_directory).
func ParseDirectory(raw []byte) (Directory, error) {
	if !utf8.Valid(raw) {
		return Directory{}, errDirectory
	}
	parts := strings.Split(string(raw), "\x00")
	n := len(parts)
	if n < 6 || n > 8 || parts[0] != "webssh-directory" || parts[n-1] != "" {
		return Directory{}, errDirectory
	}
	if n == 7 && parts[5] != "0" && parts[5] != "1" || n == 8 && !slices.Contains([]string{"", "0", "1"}, parts[5]) {
		return Directory{}, errDirectory
	}
	pid, ready, shell, path := parts[1], parts[2], parts[3], parts[4]
	id, err := strconv.ParseUint(pid, 10, 64)
	switch {
	case err != nil || id == 0 || strings.TrimLeft(pid, "0123456789") != "",
		ready != "0" && ready != "1",
		!slices.Contains(directShells, shell),
		!strings.HasPrefix(path, "/"), len(path) > 4096,
		strings.ContainsFunc(path, func(r rune) bool { return r < 32 || r >= 127 && r <= 159 }):
		return Directory{}, errDirectory
	}
	d := Directory{Path: path, ShellReady: ready == "1", ShellID: pid, Shell: shell}
	if n >= 7 && parts[5] != "" {
		v := parts[5] == "1"
		d.BracketedPaste = &v
	}
	if n == 8 && shell == "bash" && parts[6] != "" {
		m := promptPattern.FindStringSubmatch(parts[6])
		if m == nil {
			return Directory{}, errDirectory
		}
		if m[1] == pid {
			g, _ := strconv.ParseInt(m[2], 10, 64)
			d.Prompt = &Prompt{Generation: g, Phase: m[3]}
		}
	}
	return d, nil
}

// Execer runs one command on an SSH connection (*client.Conn).
type Execer interface {
	Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error)
}

// Directory probe failures, the reasons of collect_directory.
var (
	ErrDirectoryUnsupported = errors.New("directory following is not supported on this host")
	ErrDirectoryUnavailable = errors.New("the terminal directory is unavailable")
)

// DirectoryTimeout bounds one probe (two seconds in the Python release).
const DirectoryTimeout = 2 * time.Second

const maxDirectoryAnswer = 8192

// CollectDirectory runs the probe on conn. The caller serializes probes
// per session and refuses sessions whose PTY belongs to herdr.
func CollectDirectory(ctx context.Context, conn Execer, tmuxSession string) (Directory, error) {
	ctx, cancel := context.WithTimeout(ctx, DirectoryTimeout)
	defer cancel()
	out := &capped{max: maxDirectoryAnswer}
	status, err := conn.Exec(ctx, DirectoryCommand(tmuxSession), nil, out, io.Discard)
	switch {
	case err != nil:
		return Directory{}, ErrDirectoryUnavailable
	case out.over:
		return Directory{}, ErrDirectoryUnsupported
	case status != 0:
		return Directory{}, ErrDirectoryUnsupported
	}
	d, err := ParseDirectory(out.Bytes())
	if err != nil {
		return Directory{}, ErrDirectoryUnsupported
	}
	return d, nil
}

// capped keeps at most max bytes and notes that more arrived.
type capped struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.max - c.Len(); len(p) > room {
		c.over = true
		p = p[:max(room, 0)]
	}
	c.Buffer.Write(p)
	return n, nil
}
