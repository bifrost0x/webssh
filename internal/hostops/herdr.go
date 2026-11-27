package hostops

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Herdr is read only: WebSSH asks a connected host's Herdr server for its
// session snapshot and never starts it. Everything Herdr reports is
// untrusted; agents and any process with access to its socket choose the
// names, labels and paths, so only a small, bounded and cleaned agent
// list leaves this file (app/herdr.py).

// Limits of a snapshot.
const (
	herdrMaxSnapshot = 262144
	herdrMaxAgents   = 64
	herdrMaxPanes    = 256
	herdrMaxName     = 120
	herdrMaxPath     = 512
	herdrMaxError    = 4096
)

// One lookup prefix for every Herdr command, so the overview and the
// session mode resolve the same binary: the official installer places it
// in ~/.local/bin, which a non-login exec channel does not search. The
// candidates are appended, so the account's own PATH keeps priority, and
// the single-quoted script reaches sh unchanged whatever the login shell.
const herdrPathPrefix = `PATH="$PATH:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin"`

// Command lines of Herdr, the same text as the Python release. The CLI
// waits for its server without a deadline and closing an exec channel
// without a PTY does not signal the remote process, so a watchdog on the
// host ends a stuck snapshot; it is detached from the channel's output and
// the call's exit status is kept.
const (
	HerdrProbeCommand    = "sh -c '" + herdrPathPrefix + "; command -v herdr >/dev/null 2>&1'"
	HerdrSessionCommand  = "sh -c '" + herdrPathPrefix + "; exec herdr'"
	herdrSnapshotCommand = "sh -c '" + herdrPathPrefix + "; herdr api snapshot & p=$!; " +
		`(sleep 5; kill "$p") >/dev/null 2>&1 & w=$!; ` +
		`wait "$p"; s=$?; kill "$w" >/dev/null 2>&1; exit "$s"` + "'"
)

var (
	herdrStatuses = []string{"idle", "working", "blocked", "done", "unknown"}
	herdrAgentID  = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,64}$`)
	errHerdrShape = errors.New("hostops: unusable Herdr snapshot")
)

// herdrRemoved reports control, format (bidirectional overrides among
// them), surrogate, private-use and unassigned characters and the two
// Unicode line separators.
func herdrRemoved(r rune) bool {
	if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Co, unicode.Zl, unicode.Zp) {
		return true
	}
	return !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Zs)
}

// herdrText is _text: a string value cleaned and cut to limit characters;
// anything else is "".
func herdrText(v any, limit int) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit*4 {
			break
		}
		n++
		if !herdrRemoved(r) {
			b.WriteRune(r)
		}
	}
	t := []rune(pyStrip(b.String()))
	if len(t) > limit {
		t = t[:limit]
	}
	return strings.TrimRightFunc(string(t), pyIsSpace)
}

func herdrID(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok && herdrAgentID.MatchString(s)
}

// decodeHerdr decodes a JSON document as Python's json.loads does where
// it matters here: duplicate names keep the last value.
func decodeHerdr(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errHerdrShape
	}
	var doc any
	if err := json.Unmarshal(raw, &doc, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, errHerdrShape
	}
	return doc, nil
}

// parseHerdrSnapshot is parse_snapshot: the agents of "herdr api
// snapshot" output, at most 64.
func parseHerdrSnapshot(payload []byte) ([]protocol.HerdrAgent, bool, error) {
	if len(payload) > herdrMaxSnapshot {
		return nil, false, errHerdrShape
	}
	doc, err := decodeHerdr(payload)
	if err != nil {
		return nil, false, err
	}
	top, _ := doc.(map[string]any)
	result, _ := top["result"].(map[string]any)
	if result == nil || result["type"] != "session_snapshot" {
		return nil, false, errHerdrShape
	}
	snapshot, _ := result["snapshot"].(map[string]any)
	list, isList := snapshot["agents"].([]any)
	if snapshot == nil || !isList {
		return nil, false, errHerdrShape
	}
	labels := herdrPaneLabels(snapshot["panes"])
	agents := []protocol.HerdrAgent{}
	seen := map[string]bool{}
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, ok := herdrID(entry["pane_id"])
		if !ok || seen[id] {
			continue
		}
		if len(agents) == herdrMaxAgents {
			return agents, true, nil
		}
		seen[id] = true
		status, _ := entry["agent_status"].(string)
		if !slices.Contains(herdrStatuses, status) {
			status = "unknown"
		}
		kind := herdrText(entry["display_agent"], herdrMaxName)
		if kind == "" {
			kind = herdrText(entry["agent"], herdrMaxName)
		}
		label := herdrText(entry["name"], herdrMaxName)
		if label == "" {
			label = labels[id]
		}
		agents = append(agents, protocol.HerdrAgent{ID: id, Kind: kind, Label: label, CWD: herdrText(entry["cwd"], herdrMaxPath), Status: status})
	}
	return agents, false, nil
}

func herdrPaneLabels(v any) map[string]string {
	labels := map[string]string{}
	panes, _ := v.([]any)
	for _, item := range panes[:min(len(panes), herdrMaxPanes)] {
		pane, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := herdrID(pane["pane_id"]); ok {
			if _, dup := labels[id]; !dup {
				labels[id] = herdrText(pane["label"], herdrMaxName)
			}
		}
	}
	return labels
}

// herdrFailure is _failure_reason: the public reason of a failed CLI
// call from its exit status and the last JSON error line on stderr.
func herdrFailure(status int, stderr []byte) string {
	if status == 127 {
		return "not_installed"
	}
	if status != 1 {
		return "unavailable"
	}
	lines := bytesSplitLines(stderr)
	for _, line := range slices.Backward(lines) {
		doc, err := decodeHerdr(line)
		if err != nil {
			continue
		}
		top, _ := doc.(map[string]any)
		e, _ := top["error"].(map[string]any)
		code, ok := e["code"].(string)
		if !ok {
			continue
		}
		switch code {
		case "server_not_running":
			return "no_server"
		case "protocol_mismatch":
			return "incompatible"
		}
		return "unavailable"
	}
	return "unavailable"
}

// bytesSplitLines is bytes.splitlines(): \n, \r and \r\n.
func bytesSplitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexAny(b, "\r\n")
		if i < 0 {
			return append(out, b)
		}
		out = append(out, b[:i])
		if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
			i++
		}
		b = b[i+1:]
	}
	return out
}
