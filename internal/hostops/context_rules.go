package hostops

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits of a host context, as in app/host_context.py.
const (
	MaxContextEntries     = 20        // directories, and command-set references
	MaxContextPathBytes   = 4096      // one directory, UTF-8 bytes
	MaxContextRefRunes    = 128       // one command-set reference
	MaxContextProfileID   = 128       // characters of a profile id
	MaxContextContent     = 512 << 10 // one saved context, encoded
	MaxContextStoreBytes  = 4 << 20   // every context of one user, encoded
	MaxHostContexts       = 2000      // contexts of one user
	maxContextNoteRunes   = 100000
	contextDocumentPrefix = len(`{"version": 1, "hosts": {`) + len(`}}`)
)

// Content is what the page edits of a host context.
type Content struct {
	Notes       string
	Directories []string
	CommandSets []string
}

// HostContext is a stored host context. Revision 0 means none was saved.
type HostContext struct {
	Content
	Revision int64
}

// validContent is _valid_content: the notes, at most 20 distinct absolute
// printable directories of at most 4096 bytes, and at most 20 distinct
// command-set references of 1 to 128 characters.
func validContent(c Content) bool {
	if utf8.RuneCountInString(c.Notes) > maxContextNoteRunes {
		return false
	}
	for _, list := range [][]string{c.Directories, c.CommandSets} {
		if len(list) > MaxContextEntries || !distinct(list) {
			return false
		}
	}
	for _, d := range c.Directories {
		if !strings.HasPrefix(d, "/") || len(d) > MaxContextPathBytes || strings.IndexFunc(d, notPrintable) >= 0 {
			return false
		}
	}
	for _, r := range c.CommandSets {
		if n := utf8.RuneCountInString(r); n == 0 || n > MaxContextRefRunes {
			return false
		}
	}
	return true
}

// notPrintable mirrors the negation of str.isprintable() for one code
// point: categories Other and Separator, except the ASCII space.
func notPrintable(r rune) bool { return !unicode.IsPrint(r) }

func distinct(list []string) bool {
	seen := make(map[string]bool, len(list))
	for _, s := range list {
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// textSize is the length of s as json.dumps writes it with
// ensure_ascii=False: UTF-8, with the short escapes and \u00XX for the
// other control characters.
func textSize(s string) int {
	size := 2
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t' || c == '\b' || c == '\f':
			size += 2
		case c < 0x20:
			size += 6
		default:
			size++
		}
	}
	return size
}

func listSize(list []string) int {
	if len(list) == 0 {
		return 2
	}
	size := 2 + 2*(len(list)-1) // brackets and ", "
	for _, s := range list {
		size += textSize(s)
	}
	return size
}

// contentSize is the length of json.dumps(content, ensure_ascii=False).
func contentSize(c Content) int {
	return len(`{"notes": , "directories": , "command_sets": }`) +
		textSize(c.Notes) + listSize(c.Directories) + listSize(c.CommandSets)
}

// entrySize is the length of one member "profile_id": {…, "revision": n}
// of the stored document, without the separator.
func entrySize(profileID string, c HostContext) int {
	revision := len(strconv.FormatInt(c.Revision, 10))
	return textSize(profileID) + len(": ") + contentSize(c.Content) + len(`, "revision": `) + revision
}
