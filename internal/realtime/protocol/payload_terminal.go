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
	// LastSeq is the sequence of the last output chunk; terminal.attach
	// with after_seq = LastSeq replays nothing.
	LastSeq uint64 `json:"last_seq"`
}

// Auth types of terminal.open.
const (
	AuthPassword = "password"
	AuthKey      = "key"
)

// TerminalOpen asks for a new SSH terminal on channel Ch. RequestID ties
// prompts, cancellation and late results to this attempt.
type TerminalOpen struct {
	Ch        uint32     `json:"ch"`
	RequestID string     `json:"request_id"`
	Cols      int        `json:"cols"`
	Rows      int        `json:"rows"`
	Target    OpenTarget `json:"target"`
}

// OpenTarget is the connection the user asked for. A ProfileID makes the
// server resolve the saved profile; the other fields are then ignored
// except the password typed for this attempt.
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
}

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
	case t.AuthType != AuthPassword && t.AuthType != AuthKey:
		return errors.New("auth_type must be password or key")
	case t.Port < 0 || t.Port > 65535:
		return errors.New("port is out of range")
	case t.ProfileID == "" && t.Host == "":
		return errors.New("host or profile_id is required")
	}
	return nil
}

// TerminalCancel aborts a pending terminal.open.
type TerminalCancel struct {
	RequestID string `json:"request_id"`
}

// SessionRef names a terminal session (terminal.discard_late,
// terminal.close).
type SessionRef struct {
	SessionID string `json:"session_id"`
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
