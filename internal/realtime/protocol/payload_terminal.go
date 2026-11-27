package protocol

import (
	"errors"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Hello is the first message of every connection, sent before any request
// is read. Restorable lists the user's terminal sessions that survive a
// reload; the browser re-attaches with terminal.attach.
type Hello struct {
	User       HelloUser     `json:"user"`
	Schema     int           `json:"schema"`
	Restorable []SessionInfo `json:"restorable"`
	// Persistent are the account's persistent (tmux) sessions that no
	// terminal is attached to; the page offers to reconnect them
	// (persistent_session_available).
	Persistent []SessionInfo `json:"persistent"`
}

// HelloUser is the signed-in user as the page may show it.
type HelloUser struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
}

// SessionInfo describes one terminal session. The fields are those of the
// Socket.IO events ssh_connected and ssh_session_restored; empty strings
// stand for null there, and the shim converts them.
type SessionInfo struct {
	SessionID           string `json:"session_id"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	Username            string `json:"username"`
	AuthType            string `json:"auth_type"`
	KeyID               string `json:"key_id"`
	ProfileID           string `json:"profile_id"`
	ViaJump             string `json:"via_jump"`
	JumpHostID          string `json:"jump_host_id"`
	SOCKSProxyID        string `json:"socks_proxy_id"`
	ViaSOCKS            bool   `json:"via_socks"`
	ReconnectRouteKnown bool   `json:"reconnect_route_known"`
	UseTmux             bool   `json:"use_tmux"`
	TmuxSessionName     string `json:"tmux_session_name"`
	DisplayName         string `json:"display_name"`
	DetectedPlatform    string `json:"detected_platform"`
	// Herdr says the saved host grants the Herdr overview to this session
	// and the integration is on; UseHerdr that the session runs Herdr as
	// its program (herdr.session_flags of the Python release).
	Herdr    bool `json:"herdr"`
	UseHerdr bool `json:"use_herdr"`
	// LastSeq is the sequence of the last output chunk; terminal.attach
	// with after_seq = LastSeq replays nothing.
	LastSeq uint64 `json:"last_seq"`
}

// Auth types of terminal.open.
const (
	AuthPassword = "password"
	AuthKey      = "key"
	// AuthTailscale signs in with the WebSSH node's Tailscale identity
	// (NW2); no password or key is sent.
	AuthTailscale = "tailscale"
)

// TerminalOpen asks for a new SSH terminal on channel Ch. RequestID ties
// prompts, cancellation and late results to this attempt.
type TerminalOpen struct {
	Ch        uint32     `json:"ch"`
	RequestID string     `json:"request_id"`
	Cols      int        `json:"cols"`
	Rows      int        `json:"rows"`
	Target    OpenTarget `json:"target"`
	// ReplacementOf names the session this attempt replaces (reconnect
	// of a tab whose session ended); "" for a new tab.
	ReplacementOf string `json:"replacement_of,omitzero"`
}

// MaxTmuxSessionName bounds tmux_session_name (the column of the Python
// release holds 256 characters).
const MaxTmuxSessionName = 256

// OpenTarget is the connection the user asked for. A ProfileID makes the
// server resolve the saved profile; the other fields are then ignored
// except the passwords of this attempt.
//
// JumpPassword and SOCKSPassword are typed for this attempt (the password
// of proxy_jump and socks_proxy in ssh_connect); they are used only for a
// jump host with password sign-in and a SOCKS5 proxy with a login. The
// SavedPassword flags ask for the saved password assigned to the host,
// the jump host or the proxy instead (credential_id in ssh_connect).
type OpenTarget struct {
	ProfileID    string `json:"profile_id,omitzero"`
	Host         string `json:"host,omitzero"`
	Port         int    `json:"port,omitzero"`
	Username     string `json:"username,omitzero"`
	AuthType     string `json:"auth_type"`
	Password     string `json:"password,omitzero"`
	KeyID        string `json:"key_id,omitzero"`
	JumpHostID   string `json:"jump_host_id,omitzero"`
	SOCKSProxyID string `json:"socks_proxy_id,omitzero"`
	// UseTmux and TmuxSessionName ask for the session to run in tmux, as
	// the ssh_connect fields of the Python release; the terminal checks
	// the name before it reaches a shell command.
	UseTmux         bool   `json:"use_tmux,omitzero"`
	TmuxSessionName string `json:"tmux_session_name,omitzero"`
	// DisplayName names a new persistent (tmux) session; it is ignored
	// without tmux, as display_name of ssh_connect was.
	DisplayName string `json:"display_name,omitzero"`
	// UseHerdr asks for Herdr as the session's program; only a saved host
	// that grants it gets it (use_herdr of ssh_connect).
	UseHerdr bool `json:"use_herdr,omitzero"`
	// Startup is what runs after the connection is made (the
	// post-connect fields of ssh_connect); nil runs nothing.
	Startup *Startup `json:"startup,omitzero"`

	JumpPassword       string `json:"jump_password,omitzero"`
	SOCKSPassword      string `json:"socks_password,omitzero"`
	SavedPassword      bool   `json:"saved_password,omitzero"`
	JumpSavedPassword  bool   `json:"jump_saved_password,omitzero"`
	SOCKSSavedPassword bool   `json:"socks_saved_password,omitzero"`
	// Interactive says the page answers prompt.interactive and shows the
	// gateway's temporary terminal (gateway_interaction and
	// ssh_interaction of the Python release). An SSH gateway selector
	// needs it; an ordinary host gets its further keyboard-interactive
	// rounds asked with it.
	Interactive bool `json:"interactive,omitzero"`
}

// Startup is the post-connect configuration of terminal.open, with the
// members and modes of the Python release (app/post_connect_manager.py):
// Mode "none", "free_text" (Commands), "command" (CommandID with an
// optional ParametersOverride) or "command_set" (CommandSetID). An empty
// Mode is inferred as infer_mode did for older profiles.
type Startup struct {
	Mode               string  `json:"startup_mode,omitzero"`
	Commands           string  `json:"startup_commands,omitzero"`
	CommandID          string  `json:"command_id,omitzero"`
	CommandSetID       string  `json:"command_set_id,omitzero"`
	ParametersOverride *string `json:"parameters_override,omitzero"`
}

// MaxStartupBytes bounds every text member of Startup in bytes (4096
// characters of up to four bytes, MAX_STARTUP_COMMANDS_UTF8_BYTES).
const MaxStartupBytes = 4096 * 4

// TerminalOpened is the result of terminal.open.
type TerminalOpened struct {
	SessionID string      `json:"session_id"`
	Info      SessionInfo `json:"info"`
}

// Validate implements Validator.
func (r *TerminalOpen) Validate() error {
	if err := validChannel(r.Ch); err != nil {
		return err
	}
	if !validToken(r.RequestID, MaxIDLen, false) {
		return errors.New("request_id is invalid")
	}
	r.Rows, r.Cols = clampSize(r.Rows, r.Cols)
	t := r.Target
	switch {
	case t.AuthType != AuthPassword && t.AuthType != AuthKey && t.AuthType != AuthTailscale:
		return errors.New("auth_type must be password, key or tailscale")
	case t.Port < 0 || t.Port > 65535:
		return errors.New("port is out of range")
	case t.ProfileID == "" && t.Host == "":
		return errors.New("host or profile_id is required")
	case len(t.TmuxSessionName) > MaxTmuxSessionName:
		return errors.New("tmux_session_name is too long")
	case len(t.DisplayName) > MaxStartupBytes:
		return errors.New("display_name is too long")
	case t.Startup != nil && !t.Startup.bounded():
		return errors.New("startup is too long")
	case r.ReplacementOf != "" && !validToken(r.ReplacementOf, MaxIDLen, false):
		return errors.New("replacement_of is invalid")
	}
	return nil
}

func (s *Startup) bounded() bool {
	return len(s.Mode) <= 32 && len(s.Commands) <= MaxStartupBytes && len(s.CommandID) <= MaxIDLen &&
		len(s.CommandSetID) <= MaxIDLen && (s.ParametersOverride == nil || len(*s.ParametersOverride) <= MaxStartupBytes)
}

// TerminalCancel aborts a pending terminal.open.
type TerminalCancel struct {
	RequestID string `json:"request_id"`
}

// SessionRef names a terminal session (terminal.discard_late,
// terminal.close). RequestID is the request_id of the terminal.open that
// created the session; terminal.discard_late discards only a session whose
// attempt carried it, as the Python release matched client_request_id.
type SessionRef struct {
	SessionID string `json:"session_id"`
	RequestID string `json:"request_id,omitzero"`
}

// Validate implements Validator.
func (r *SessionRef) Validate() error {
	if r.RequestID != "" && !validToken(r.RequestID, MaxIDLen, false) {
		return errors.New("request_id is invalid")
	}
	return nil
}

// TerminalAttach binds an existing session to channel Ch and replays the
// output after AfterSeq.
type TerminalAttach struct {
	Ch        uint32 `json:"ch"`
	SessionID string `json:"session_id"`
	AfterSeq  uint64 `json:"after_seq"`
}

// Validate implements Validator.
func (r *TerminalAttach) Validate() error { return validChannel(r.Ch) }

// TerminalAttached is the result of terminal.attach and terminal.open's
// stream: Seq is the watermark of the replay, Full says the replay starts
// with a reset frame.
type TerminalAttached struct {
	Ch        uint32 `json:"ch"`
	SessionID string `json:"session_id"`
	Seq       uint64 `json:"seq"`
	Full      bool   `json:"full"`
}

// ChannelRef names a channel of this connection (terminal.detach).
type ChannelRef struct {
	Ch uint32 `json:"ch"`
}

// TerminalResize changes the size of the terminal on channel Ch.
type TerminalResize struct {
	Ch   uint32 `json:"ch"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// Validate implements Validator.
func (r *TerminalResize) Validate() error {
	r.Rows, r.Cols = clampSize(r.Rows, r.Cols)
	return validChannel(r.Ch)
}

// TerminalRename sets the persistent display name of a session.
type TerminalRename struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
}

// TerminalClosed tells that a session ended (event).
type TerminalClosed struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// TerminalTimeoutWarning announces the idle timeout two minutes ahead.
type TerminalTimeoutWarning struct {
	SessionID string `json:"session_id"`
}

// TerminalResync tells the browser that channel Ch lost output and must
// re-attach.
type TerminalResync struct {
	Ch        uint32 `json:"ch"`
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// TerminalInputRejected refuses the input frame ISeq on channel Ch.
type TerminalInputRejected struct {
	Ch           uint32     `json:"ch"`
	ISeq         uint64     `json:"iseq"`
	Code         fault.Code `json:"code"`
	RetryAfterMS int64      `json:"retry_after_ms,omitzero"`
}

// TerminalInputAck confirms an input frame sent with FlagWantAck.
type TerminalInputAck struct {
	Ch   uint32 `json:"ch"`
	ISeq uint64 `json:"iseq"`
}

// Channels are client-allocated; 0 and the upper half are reserved.
func validChannel(ch uint32) error {
	if ch == 0 || ch >= 1<<31 {
		return errors.New("ch must be in 1..2147483647")
	}
	return nil
}

// clampSize applies the terminal size bounds of the Python release:
// rows 1..500 (default 24), cols 1..1000 (default 80).
func clampSize(rows, cols int) (int, int) {
	clamp := func(v, lo, hi, def int) int {
		if v == 0 {
			return def
		}
		return min(max(v, lo), hi)
	}
	return clamp(rows, 1, 500, 24), clamp(cols, 1, 1000, 80)
}
