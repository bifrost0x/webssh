// Package idna2003 converts host names to their ASCII form exactly as the
// Python release did with name.encode("idna"), the IDNA 2003 codec of the
// standard library (encodings.idna, RFC 3490 with Nameprep, RFC 3491).
//
// Host keys, the network policy and the configured allowlists of the
// Python release hold names in that form, so the conversion has to match
// bit for bit, quirks included: unassigned code points are allowed,
// str.lower() of Python's current Unicode version is part of the case
// mapping, and NFKC uses the decompositions of Unicode 3.2.0 with the
// combining classes and composition pairs of the current version. The
// tables in tables.go are generated from CPython itself by
// testdata/oracle.py; the tests compare the package with that
// interpreter.
//
// Only the encoding direction exists: the Python release never decoded
// names with the codec.
package idna2003

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// ErrInvalid is returned for every name the codec refuses (Python raises
// UnicodeError): an empty or too long label, a prohibited character, a
// bidirectional violation, a label that already carries the ACE prefix,
// or input that is not valid UTF-8.
var ErrInvalid = errors.New("idna2003: invalid host name")

// acePrefix is the prefix of an encoded label (RFC 3490, section 5).
const acePrefix = "xn--"

// maxLabel is the exclusive upper bound of a label in bytes.
const maxLabel = 64

// Encode returns name in ASCII as name.encode("idna").decode("ascii")
// does. A name made only of ASCII is returned unchanged after checking
// its labels, so it keeps its case; other names are split at the four
// IDNA dots, each label is converted with ToASCII and the labels are
// joined with ".". A final empty label keeps the trailing dot.
func Encode(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if !utf8.ValidString(name) {
		return "", ErrInvalid
	}
	if isASCII(name) {
		labels := strings.Split(name, ".")
		for i, label := range labels {
			if label == "" && i < len(labels)-1 || len(label) >= maxLabel {
				return "", ErrInvalid
			}
		}
		return name, nil
	}
	labels := splitDots(name)
	trailingDot := ""
	if labels[len(labels)-1] == "" {
		trailingDot = "."
		labels = labels[:len(labels)-1]
	}
	var b strings.Builder
	for i, label := range labels {
		if i > 0 {
			b.WriteByte('.')
		}
		out, err := ToASCII(label)
		if err != nil {
			return "", err
		}
		b.WriteString(out)
	}
	b.WriteString(trailingDot)
	return b.String(), nil
}

// ToASCII converts one label as encodings.idna.ToASCII does, with
// AllowUnassigned and without the STD3 rules.
func ToASCII(label string) (string, error) {
	if !utf8.ValidString(label) {
		return "", ErrInvalid
	}
	if isASCII(label) {
		return checkedASCII(label)
	}
	prepared, err := nameprep([]rune(label))
	if err != nil {
		return "", err
	}
	if isASCIIRunes(prepared) {
		return checkedASCII(string(prepared))
	}
	if hasACEPrefix(prepared) {
		return "", ErrInvalid
	}
	// Every code point adds at least one byte to the punycode output, so a
	// label of maxLabel-len(acePrefix) code points can never fit. Stopping
	// here gives Python's result without the quadratic encoding of a long
	// label.
	if len(prepared) >= maxLabel-len(acePrefix) {
		return "", ErrInvalid
	}
	out := acePrefix + punycode(prepared)
	if len(out) >= maxLabel {
		return "", ErrInvalid
	}
	return out, nil
}

func checkedASCII(label string) (string, error) {
	if len(label) == 0 || len(label) >= maxLabel {
		return "", ErrInvalid
	}
	return label, nil
}

// hasACEPrefix is label.lower().startswith("xn--"). No character outside
// ASCII lower-cases to text containing x, n or "-" (the generator checks
// this), so folding ASCII is enough.
func hasACEPrefix(label []rune) bool {
	if len(label) < len(acePrefix) {
		return false
	}
	for i := range len(acePrefix) {
		r := label[i]
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		if r != rune(acePrefix[i]) {
			return false
		}
	}
	return true
}

// splitDots splits at the label separators of RFC 3490, section 3.1:
// full stop, ideographic full stop, fullwidth full stop and halfwidth
// ideographic full stop.
func splitDots(name string) []string {
	var labels []string
	start := 0
	for i, r := range name {
		switch r {
		case '.', '\u3002', '\uff0e', '\uff61':
			labels = append(labels, name[start:i])
			start = i + utf8.RuneLen(r)
		}
	}
	return append(labels, name[start:])
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func isASCIIRunes(rs []rune) bool {
	for _, r := range rs {
		if r >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
