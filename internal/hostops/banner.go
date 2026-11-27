package hostops

import (
	"bytes"
	"regexp"
	"strings"
)

// Banner is what an SSH identification line (RFC 4253, section 4.2) says
// about its server: the software token with its first underscore turned
// into a space, the comment and a platform hint from the host catalog.
// Only printable ASCII ever gets here; nothing else of the line is kept.
type Banner struct {
	Software string `json:"software"`
	Comment  string `json:"comment"`
	// Platform is a platform id of the host catalog, or "" when the line
	// names none.
	Platform string `json:"platform"`
}

var identification = regexp.MustCompile(`^SSH-[0-9.]+-([!-~]{1,100})(?: ([ -~]{0,120}))?$`)

// platformHint is one rule of _PLATFORM_HINTS: most specific first. A
// greeting naming windows, mikrotik or cisco suppresses the shell probe,
// so those rules are anchored to the software token.
type platformHint struct {
	platform string
	match    func(text string) bool
}

func searching(pattern string) func(string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString
}

// prefixNotFollowedBy is ^prefix(?![...]) under re.IGNORECASE, which RE2
// cannot express: prefix matched without case, then a next byte outside
// the excluded class.
func prefixNotFollowedBy(prefix *regexp.Regexp, excluded func(byte) bool) func(string) bool {
	return func(text string) bool {
		loc := prefix.FindStringIndex(text)
		if loc == nil {
			return false
		}
		return loc[1] == len(text) || !excluded(text[loc[1]])
	}
}

func asciiLetter(b byte) bool { return 'a' <= b|0x20 && b|0x20 <= 'z' }
func asciiAlnum(b byte) bool  { return asciiLetter(b) || '0' <= b && b <= '9' }

var platformHints = []platformHint{
	{"openwrt", searching(`(?i)\bopenwrt\b`)},
	{"windows", prefixNotFollowedBy(regexp.MustCompile(`(?i)^openssh[ _]for[ _]windows`), asciiLetter)},
	{"mikrotik", prefixNotFollowedBy(regexp.MustCompile(`(?i)^rosssh`), asciiAlnum)},
	{"cisco", searching(`(?i)^cisco[-_ .0-9]`)},
	{"raspberrypi", searching(`(?i)raspbian|raspberry`)},
	{"ubuntu", searching(`(?i)ubuntu`)},
	{"debian", searching(`(?i)debian`)},
	{"freebsd", searching(`(?i)freebsd`)},
	{"fedora", searching(`(?i)fedora|\.fc\d+`)},
	{"alpinelinux", searching(`(?i)alpine`)},
	{"embedded", searching(`(?i)^dropbear(?:[ _]|$)`)},
}

// DescribeBanner is describe_banner: it reads the first line of raw (up
// to the first LF, trailing CRs removed) as an SSH identification line.
// ok is false for anything else, including any byte outside printable
// ASCII.
func DescribeBanner(raw []byte) (b Banner, ok bool) {
	line, _, _ := bytes.Cut(raw, []byte{'\n'})
	line = bytes.TrimRight(line, "\r")
	m := identification.FindSubmatch(line)
	if m == nil {
		return Banner{}, false
	}
	software := strings.Replace(string(m[1]), "_", " ", 1)
	comment := string(m[2])
	text := software + " " + comment
	for _, h := range platformHints {
		if h.match(text) {
			b.Platform = h.platform
			break
		}
	}
	b.Software, b.Comment = truncate(software, 80), truncate(comment, 80)
	return b, true
}

// truncate cuts printable ASCII, where bytes are characters.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
