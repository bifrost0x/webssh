package files

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// Encoding is the text encoding the editor read a file with.
type Encoding string

const (
	EncodingUTF8   Encoding = "utf-8"
	EncodingLatin1 Encoding = "latin-1"
)

// Newline is the line ending of a file as the editor reports it.
type Newline string

const (
	NewlineLF    Newline = "lf"
	NewlineCRLF  Newline = "crlf"
	NewlineMixed Newline = "mixed"
)

// BinarySniffBytes is the prefix in which a NUL byte marks a file as binary.
const BinarySniffBytes = 1024

// Decode is the one decoding rule of preview and editor (D-23, the rule of
// app/editor_text.py): bytes with a NUL in the first BinarySniffBytes are
// binary; everything else is strict UTF-8 or, failing that, Latin-1, which
// accepts every byte. A byte order mark is kept as U+FEFF. The text is
// returned with its line endings unchanged.
//
// A preview cut inside a UTF-8 sequence decodes as Latin-1, as it did for
// SMB in the Python release; for SFTP the Python preview called such text
// binary (visible change of D-23).
func Decode(raw []byte) (text string, enc Encoding, binary bool) {
	if bytes.IndexByte(raw[:min(len(raw), BinarySniffBytes)], 0) >= 0 {
		return "", "", true
	}
	if utf8.Valid(raw) {
		return string(raw), EncodingUTF8, false
	}
	var b strings.Builder
	b.Grow(len(raw) * 2)
	for _, c := range raw {
		b.WriteRune(rune(c))
	}
	return b.String(), EncodingLatin1, false
}

// DetectNewline returns NewlineLF when raw has no CRLF, NewlineCRLF when
// every LF ends a CRLF, and NewlineMixed otherwise. A lone CR is no line
// ending.
func DetectNewline(raw []byte) Newline {
	crlf := bytes.Count(raw, []byte("\r\n"))
	switch {
	case crlf == 0:
		return NewlineLF
	case crlf == bytes.Count(raw, []byte("\n")):
		return NewlineCRLF
	}
	return NewlineMixed
}

// EditorText is the text the browser editor gets: CRLF becomes LF, the
// only line ending a textarea knows. Saving converts back by Newline.
func EditorText(text string) string {
	return strings.ReplaceAll(text, "\r\n", "\n")
}

// Revision identifies file content for the stale-save check: the
// lower-case hex SHA-256 of all bytes, as in the Python release.
func Revision(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
