package hosts

import (
	"bytes"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Answers of a probe that gave no facts.
const (
	// answerStalled: our probe printed its own lines and then hung (pmxcfs,
	// D-Bus, a stale mount, a container query). Asked again after a day.
	answerStalled = "stalled"
	// answerSilent: nothing printable yet, maybe a login shell that starts
	// slowly. Asked again after a day.
	answerSilent = "silent"
	// answerUnsupported: other readable text, a forced command or menu.
	// Not asked again this week.
	answerUnsupported = "unsupported"
)

// terminalSequence is _TERMINAL_SEQUENCE: ANSI CSI and OSC sequences.
var terminalSequence = regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\|$)")

func hasProbeLine(text string) bool {
	for _, line := range probeLines(text) {
		key, _, found := strings.Cut(line, "=")
		if found && !strings.ContainsFunc(line, isControl) && (singleKeys[key] || repeatedKeys[key]) {
			return true
		}
	}
	return false
}

// identityAtDeadline is _identity_at_deadline: it decides an answer that
// had not ended when the deadline passed. The probe prints os-release and
// its kernel line within milliseconds; with a complete line of its own
// key=value form it is our probe that hung, and what comes later is
// missing, so no fact is stored.
func identityAtDeadline(output []byte) string {
	if len(output) == 0 {
		return answerSilent
	}
	complete := output[:bytes.LastIndexByte(output, '\n')+1]
	if !utf8.Valid(complete) {
		return answerUnsupported
	}
	id, err := ParseIdentity(string(complete))
	if err != nil {
		return answerUnsupported
	}
	if id.State == StateDetected || hasProbeLine(string(complete)) {
		return answerStalled
	}
	// Nothing printable besides colour, cursor or window title sequences
	// (a startup file preparing the terminal): no menu was shown yet.
	text := strings.ToValidUTF8(string(output), "�")
	rest := strings.Map(func(r rune) rune {
		if isControl(r) {
			return -1
		}
		return r
	}, terminalSequence.ReplaceAllString(text, ""))
	if pyStrip(rest) == "" {
		return answerSilent
	}
	return answerUnsupported
}
