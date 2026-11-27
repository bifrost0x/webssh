package terminal

import (
	"bytes"
	"regexp"
)

// The prompt state of a session tells the directory probe of the file
// area whether the shell shows a prompt that nobody typed into
// (input_idle of request_session_directory). A shell that supports
// bracketed paste turns it on (CSI ? 2004 h) when it draws its prompt and
// off when it runs a command; an alternate screen (CSI ? 1049/1047/47 h)
// means a full-screen program is in front. The rules are those of
// _note_prompt_output, _note_prompt_input and prompt_input_idle of the
// Python release (app/ssh_manager.py).
var (
	promptMode       = regexp.MustCompile(`\x1b\[\?(2004|1049|1047|47)([hl])`)
	promptModePrefix = regexp.MustCompile(`\x1b(?:\[(?:\?[0-9]{0,4})?)?$`)
	// terminalReplies are answers of the browser terminal to queries of
	// the remote (device attributes, OSC 10/11/12 colours); they are not
	// typing.
	terminalReplies = regexp.MustCompile(`(?i)\x1b\[[?>]?[0-9;]*c` +
		`|\x1b\](?:10|11|12);rgb:[0-9a-f]{1,4}/[0-9a-f]{1,4}/[0-9a-f]{1,4}(?:\x1b\\|\x07)`)
)

// promptState is guarded by the session's mutex.
type promptState struct {
	idle      bool
	alternate bool
	// tail is an unfinished mode sequence at the end of the last output,
	// at most 8 bytes, so a sequence split across reads counts once.
	tail []byte
}

// output notes one output chunk.
func (p *promptState) output(data []byte) {
	scan := append(append([]byte(nil), p.tail...), data...)
	for _, m := range promptMode.FindAllSubmatch(scan, -1) {
		on := m[2][0] == 'h'
		if string(m[1]) == "2004" {
			p.idle = on
		} else {
			p.alternate = on
		}
	}
	last := scan[max(0, len(scan)-8):]
	p.tail = append(p.tail[:0], promptModePrefix.Find(last)...)
}

// input notes input about to reach the shell: anything but terminal
// replies leaves the prompt. Invalid UTF-8 is ignored as the Python
// release decoded with errors="ignore".
func (p *promptState) input(data []byte) {
	text := bytes.ToValidUTF8(data, nil)
	if len(terminalReplies.ReplaceAll(text, nil)) > 0 {
		p.idle = false
	}
}

// inputIdle is prompt_input_idle.
func (p *promptState) inputIdle() bool { return p.idle && !p.alternate }

// InputIdle reports whether the session shows a prompt and nothing was
// typed since (input_idle of the session directory). It holds the
// session's lock only to read the state.
func (s *Session) InputIdle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prompt.inputIdle()
}
