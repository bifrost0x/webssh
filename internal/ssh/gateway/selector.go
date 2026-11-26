// Package gateway connects through an SSH gateway such as Warpgate. WebSSH
// is the client: it dials the gateway with the shared SSH dialer
// (internal/ssh/client, as a client.Variant), sends a "user:target"
// selector as the username, answers the gateway's authentication prompts
// through the browser (prompt.interactive) and proves that the target is
// ready before any terminal setup runs. Nothing here accepts SSH
// connections.
package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
)

// MaxSelectorBytes bounds the selector in UTF-8 bytes.
const MaxSelectorBytes = 128

// Selector refusals, with the texts of the Python release.
var (
	ErrInvalidSelector = fault.New(fault.InvalidValue, "Invalid gateway selector")
	errTicket          = fault.New(fault.InvalidValue, "Gateway tickets and alternate separators are not supported")
	errSelectorLength  = fault.New(fault.InvalidValue, "Gateway selector exceeds 128 UTF-8 bytes")
	errSelectorParts   = fault.New(fault.InvalidValue, "Gateway user and target are required without surrounding whitespace")
)

// IsSelector reports whether a username opts into the gateway path.
func IsSelector(username string) bool { return strings.Contains(username, ":") }

// ParseSelector returns the exact user and target of "user:target", as
// parse_selector of the Python release. The target may contain further
// colons. Control, format, surrogate and line or paragraph separator
// characters are refused, as are ticket selectors and invalid UTF-8.
func ParseSelector(value string) (user, target string, err error) {
	if !strings.Contains(value, ":") || !utf8.ValidString(value) {
		return "", "", ErrInvalidSelector
	}
	if strings.HasPrefix(value, "ticket-") || strings.Contains(value, "#") {
		return "", "", errTicket
	}
	for _, r := range value {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Zl, unicode.Zp) {
			return "", "", ErrInvalidSelector
		}
	}
	if len(value) > MaxSelectorBytes {
		return "", "", errSelectorLength
	}
	user, target, _ = strings.Cut(value, ":")
	if user == "" || target == "" || user != strings.TrimSpace(user) || target != strings.TrimSpace(target) {
		return "", "", errSelectorParts
	}
	return user, target, nil
}

// TmuxName names the persistent tmux session of a gateway terminal
// (tmux_name of the Python release; the terminal builds tmux sessions).
// The digest input is the JSON array Python's json.dumps writes for
// [str(user_id), host, int(port), selector] with ensure_ascii, so Go and
// Python derive the same 16-character digest; a random suffix follows.
func TmuxName(prefix, host string, port int, selector string, userID int64) (string, error) {
	if _, _, err := ParseSelector(selector); err != nil {
		return "", err
	}
	var safe strings.Builder
	for _, r := range prefix {
		if safe.Len() >= 80 {
			break
		}
		if r < utf8.RuneSelf && (r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			safe.WriteRune(r)
		} else {
			safe.WriteByte('_')
		}
	}
	identity := "[" + pyJSONString(strconv.FormatInt(userID, 10)) + ", " + pyJSONString(host) + ", " +
		strconv.Itoa(port) + ", " + pyJSONString(selector) + "]"
	digest := sha256.Sum256([]byte(identity))
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("gateway: tmux suffix: %w", err)
	}
	return safe.String() + "_wg_" + hex.EncodeToString(digest[:])[:16] + "_" + hex.EncodeToString(suffix[:]), nil
}

// pyJSONString encodes s like Python's json.dumps(s, ensure_ascii=True).
func pyJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || r >= 0x7f && r <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, r)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
