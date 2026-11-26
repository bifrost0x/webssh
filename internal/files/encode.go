package files

import (
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
)

// maxDiffComparisons bounds the line alignment of a save with mixed line
// endings: above this many line pairs the changed region is mapped by
// position instead (as in app/editor_text.py).
const maxDiffComparisons = 2_000_000

// EncodeEditorText turns the text of the browser editor back into the
// bytes of the file it was opened from (encode_editor_text of the Python
// release): CRLF from the browser becomes LF, then NewlineCRLF converts
// every LF, and NewlineMixed keeps the ending of each unchanged line,
// while new or changed lines take the ending of the line they replace or
// follow. original holds the revision-checked bytes of the file and is
// needed for NewlineMixed only. An unknown encoding is UTF-8, an unknown
// newline mode is LF.
//
// A character the encoding cannot store fails with
// fault.EditEncodingUnsupported; its details name the character and the
// one-based line.
func EncodeEditorText(content string, enc Encoding, nl Newline, original []byte) ([]byte, error) {
	if enc != EncodingLatin1 {
		enc = EncodingUTF8
	}
	text := strings.ReplaceAll(content, "\r\n", "\n")
	switch nl {
	case NewlineCRLF:
		text = strings.ReplaceAll(text, "\n", "\r\n")
	case NewlineMixed:
		if original == nil {
			return nil, fault.New(fault.InvalidRequest, "")
		}
		text = mergeLineEndings(text, decodeAs(original, enc))
	}
	if enc == EncodingUTF8 {
		return []byte(text), nil
	}
	out := make([]byte, 0, len(text))
	for i, r := range text {
		if r > 0xff {
			return nil, encodingError(r, enc, 1+strings.Count(text[:i], "\n"))
		}
		out = append(out, byte(r)) // #nosec G115 -- r <= 0xff is checked above
	}
	return out, nil
}

// decodeAs decodes bytes that Decode already accepted with enc.
func decodeAs(raw []byte, enc Encoding) string {
	if enc == EncodingUTF8 {
		return strings.ToValidUTF8(string(raw), "�")
	}
	var b strings.Builder
	b.Grow(len(raw) * 2)
	for _, c := range raw {
		b.WriteRune(rune(c))
	}
	return b.String()
}

func encodingError(r rune, enc Encoding, line int) error {
	e := fault.New(fault.EditEncodingUnsupported,
		"The text contains a character that cannot be saved in this "+string(enc)+" file. Remove or replace it before saving.")
	e.Details = map[string]any{"character": string(r), "line": line}
	return e
}

// splitLines splits text into bodies and endings; the last body has none.
func splitLines(text string) (bodies, endings []string) {
	parts := strings.Split(text, "\n")
	for _, p := range parts[:len(parts)-1] {
		if body, ok := strings.CutSuffix(p, "\r"); ok {
			bodies, endings = append(bodies, body), append(endings, "\r\n")
		} else {
			bodies, endings = append(bodies, p), append(endings, "\n")
		}
	}
	return append(bodies, parts[len(parts)-1]), append(endings, "")
}

// mergeLineEndings is _merge_line_endings of app/editor_text.py.
func mergeLineEndings(text, originalText string) string {
	oldBodies, oldEndings := splitLines(originalText)
	newBodies := strings.Split(text, "\n")
	terminated := len(newBodies) - 1
	crlf, lf := 0, 0
	for _, e := range oldEndings {
		switch e {
		case "\r\n":
			crlf++
		case "\n":
			lf++
		}
	}
	def := "\n"
	if crlf > lf {
		def = "\r\n"
	}
	or := func(e string) string {
		if e == "" {
			return def
		}
		return e
	}
	// near is the ending of the old line at index or the closest one
	// before it.
	near := func(index int) string {
		for c := min(index, len(oldEndings)-1); c >= 0; c-- {
			if oldEndings[c] != "" {
				return oldEndings[c]
			}
		}
		return def
	}

	endings := make([]string, len(newBodies))
	limit := min(len(oldBodies), len(newBodies))
	prefix := 0
	for prefix < limit && oldBodies[prefix] == newBodies[prefix] {
		endings[prefix] = or(oldEndings[prefix])
		prefix++
	}
	suffix := 0
	for suffix < limit-prefix && oldBodies[len(oldBodies)-1-suffix] == newBodies[len(newBodies)-1-suffix] {
		endings[len(newBodies)-1-suffix] = or(oldEndings[len(oldEndings)-1-suffix])
		suffix++
	}

	oldMiddle := oldBodies[prefix : len(oldBodies)-suffix]
	newMiddle := newBodies[prefix : len(newBodies)-suffix]
	var blocks []lineBlock
	switch {
	case len(oldMiddle)*len(newMiddle) > maxDiffComparisons:
		blocks = []lineBlock{{0, len(oldMiddle), 0, len(newMiddle)}}
	case len(newMiddle) >= len(oldMiddle):
		blocks = lineOpcodes(oldMiddle, newMiddle)
	default:
		// autojunk applies to the second sequence only, so the longer
		// side goes there (as in Python).
		for _, b := range lineOpcodes(newMiddle, oldMiddle) {
			blocks = append(blocks, lineBlock{b.j1, b.j2, b.i1, b.i2})
		}
	}
	for _, b := range blocks {
		i1, i2, j1, j2 := b.i1+prefix, b.i2+prefix, b.j1+prefix, b.j2+prefix
		for offset := range j2 - j1 {
			if i1 == i2 {
				endings[j1+offset] = near(i1 - 1)
				continue
			}
			old := min(i1+offset, i2-1)
			if oldEndings[old] != "" {
				endings[j1+offset] = oldEndings[old]
			} else {
				endings[j1+offset] = near(old)
			}
		}
	}

	var out strings.Builder
	out.Grow(len(text) + len(newBodies))
	for i, body := range newBodies {
		out.WriteString(body)
		if i < terminated {
			out.WriteString(endings[i])
		}
	}
	return out.String()
}
