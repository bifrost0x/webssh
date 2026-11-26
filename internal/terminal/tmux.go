package terminal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Connections dials a target and leaves its channels to the caller, so a
// tmux session can run beside the commands that probe and end it.
// *client.Dialer provides it.
type Connections interface {
	Dial(ctx context.Context, t client.Target, ix client.Interaction) (*client.Conn, error)
}

// Time limits of the tmux commands (Python: 3 s for the probe, the
// configured TMUX_PROBE_TIMEOUT and TMUX_KILL_TIMEOUT for the others).
const (
	tmuxProbeTimeout = 3 * time.Second
	tmuxCmdTimeout   = 5 * time.Second
	// tmuxEndTimeout bounds what happens when a tmux session ends: one
	// command and one store write.
	tmuxEndTimeout = 15 * time.Second
)

// maxTmuxName is the longest name a reattach accepts, and the length new
// names are kept within (Python: ^[A-Za-z0-9_]{1,190}$ on reconnect).
const maxTmuxName = 190

var tmuxNamePattern = regexp.MustCompile(`\A[A-Za-z0-9_]{1,190}\z`)

// validTmuxName reports whether name may be attached to. Only such names
// ever reach a command line.
func validTmuxName(name string) bool { return tmuxNamePattern.MatchString(name) }

var errTmuxName = fault.New(fault.InvalidValue, "Invalid tmux session name")

// tmuxSafe replaces every character other than ASCII letters, digits and
// _ with _, as tmux would turn . and : into _ and refuse to match the name
// afterwards.
func tmuxSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' {
			return r
		}
		return '_'
	}, s)
}

// newTmuxName builds the name of a new tmux session with the scheme of the
// Python release: {prefix}_{user}_{host}_{port}_{8 random hex digits}.
// The host part is shortened so the name stays reattachable.
func newTmuxName(prefix, user, host string, port int) string {
	if prefix = tmuxSafe(prefix); prefix == "" {
		prefix = "webssh"
	}
	prefix = prefix[:min(len(prefix), 80)]
	user = tmuxSafe(user)
	user = user[:min(len(user), 32)]
	var b [4]byte
	_, _ = rand.Read(b[:])
	tail := "_" + strconv.Itoa(port) + "_" + hex.EncodeToString(b[:])
	h := tmuxSafe(host)
	h = h[:max(0, min(len(h), maxTmuxName-len(prefix)-len(user)-len(tail)-2))]
	return prefix + "_" + user + "_" + h + tail
}

// tmuxAttachCommand starts tmux as the session's program: a new session,
// or for a reattach the existing one (created again if it is gone), with
// mouse input enabled for exactly this session. The name is a checked
// token; nothing else on the line is variable.
func tmuxAttachCommand(name string, reattach bool) (string, error) {
	if !validTmuxName(name) {
		return "", errTmuxName
	}
	n, err := remotecmd.Word(name)
	if err != nil {
		return "", err
	}
	target, err := remotecmd.Word("=" + name + ":")
	if err != nil {
		return "", err
	}
	attach := "new-session"
	if reattach {
		attach = "new-session -A"
	}
	return "tmux " + attach + " -s " + n + ` \; set-option -t ` + target + " mouse on", nil
}

// tmuxTargetCommand is "tmux <verb> -t '=<name>'": "=" asks for the exact
// name, without it tmux falls back to a prefix match.
func tmuxTargetCommand(verb, name string) (string, error) {
	if !validTmuxName(name) {
		return "", errTmuxName
	}
	target, err := remotecmd.Word("=" + name)
	if err != nil {
		return "", err
	}
	return "tmux " + verb + " -t " + target, nil
}

const tmuxProbeCommand = "command -v tmux"

// remoteHost is a connection with the operations a tmux session needs.
type remoteHost interface {
	run(ctx context.Context, line string, timeout time.Duration) (status int, stderr []byte, err error)
	commandShell(ctx context.Context, line string, rows, cols int) (client.Shell, error)
	shell(ctx context.Context, rows, cols int) (client.Shell, error)
	Close() error
}

// connHost runs commands through remotecmd on a client connection.
type connHost struct{ c *client.Conn }

func (h connHost) run(ctx context.Context, line string, timeout time.Duration) (int, []byte, error) {
	r, err := remotecmd.Run(ctx, h.c, remotecmd.Command{Line: line, Timeout: timeout, MaxOutput: 4 << 10})
	return r.ExitStatus, r.Stderr, err
}

func (h connHost) commandShell(ctx context.Context, line string, rows, cols int) (client.Shell, error) {
	return h.c.CommandShell(ctx, line, rows, cols)
}

func (h connHost) shell(ctx context.Context, rows, cols int) (client.Shell, error) {
	return h.c.Shell(ctx, rows, cols)
}

func (h connHost) Close() error { return h.c.Close() }

// ownedShell closes its connection with the shell.
type ownedShell struct {
	client.Shell
	host remoteHost
}

func (s ownedShell) Close() error {
	err := s.Shell.Close()
	if cerr := s.host.Close(); err == nil {
		err = cerr
	}
	return err
}

// tmuxBinding is the tmux session behind a terminal session.
type tmuxBinding struct {
	name     string
	reattach bool
	host     remoteHost
	recorded bool // a row was stored; set before the session is visible
}

// tmuxPlan is what terminal.open asked for after the checks.
type tmuxPlan struct {
	use         bool
	name        string
	reattach    bool
	displayName string
}

func (m *Manager) tmuxOn(ctx context.Context) bool {
	return m.store.db != nil && m.dialHost != nil && m.tmuxEnabled != nil && m.tmuxEnabled(ctx)
}

// planTmux checks the tmux fields of terminal.open before anything is
// dialled. A name the user owns is reattached; an unknown one starts a new
// session, as the Python release did.
func (m *Manager) planTmux(ctx context.Context, owner int64, req protocol.OpenTarget, t client.Target) (tmuxPlan, error) {
	if !req.UseTmux || !m.tmuxOn(ctx) {
		return tmuxPlan{}, nil
	}
	plan := tmuxPlan{use: true, name: newTmuxName(m.cfg.TmuxPrefix, t.Hop.User, t.Hop.Host, t.Hop.Port)}
	name := req.TmuxSessionName
	if name == "" {
		return plan, nil
	}
	if !validTmuxName(name) {
		return tmuxPlan{}, errTmuxName
	}
	row, found, err := m.store.byName(ctx, owner, name)
	if err != nil {
		return tmuxPlan{}, fault.Wrap(fault.StorageError, err, "")
	}
	if !found {
		return plan, nil
	}
	saved := t.Display.SOCKSProxyID
	stored := row.SOCKSProxyID.String
	if (stored != "" || row.ViaSOCKS || saved != "") && (stored == "" || stored != saved) {
		return tmuxPlan{}, invalid("This persistent session uses a different SOCKS5 route. Close it and connect again.")
	}
	return tmuxPlan{use: true, name: name, reattach: true, displayName: row.DisplayName.String}, nil
}

// openShell opens the session's shell: tmux when planned and installed on
// the host, else the login shell.
func (m *Manager) openShell(ctx context.Context, t client.Target, ix client.Interaction, rows, cols int, plan tmuxPlan) (client.Shell, *tmuxBinding, error) {
	if !plan.use {
		sh, err := m.shells.OpenShell(ctx, t, ix, rows, cols)
		return sh, nil, err
	}
	line, err := tmuxAttachCommand(plan.name, plan.reattach)
	if err != nil {
		return nil, nil, err
	}
	h, err := m.dialHost(ctx, t, ix)
	if err != nil {
		return nil, nil, err
	}
	// Probe on a separate channel: no error text to match, and tmux's
	// first screen is not swallowed.
	status, _, err := h.run(ctx, tmuxProbeCommand, tmuxProbeTimeout)
	if ctx.Err() != nil {
		_ = h.Close()
		return nil, nil, ctx.Err()
	}
	if err != nil || status != 0 {
		m.log.Warn("tmux not found on target host, falling back to regular shell", "host", t.Hop.Host, "port", t.Hop.Port)
		sh, err := h.shell(ctx, rows, cols)
		if err != nil {
			_ = h.Close()
			return nil, nil, err
		}
		return ownedShell{sh, h}, nil, nil
	}
	sh, err := h.commandShell(ctx, line, rows, cols)
	if err != nil {
		_ = h.Close()
		return nil, nil, err
	}
	return ownedShell{sh, h}, &tmuxBinding{name: plan.name, reattach: plan.reattach, host: h}, nil
}
