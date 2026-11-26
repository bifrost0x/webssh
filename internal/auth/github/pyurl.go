package github

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The redirect URI is checked exactly as app/github_auth_service.py does
// with urllib.parse.urlsplit (CPython 3.15): a stored URI that Python
// accepted must stay active after the update, and one it refused must
// stay refused. pysplit reproduces the parts of urlsplit the check reads;
// testdata/pyprobe.py compares it with the Python release.

var errPyURL = errors.New("github: invalid URL")

// pyURL is the result of urlsplit with the netloc properties the check
// uses.
type pyURL struct {
	scheme, netloc, path, query, fragment string
}

const c0OrSpace = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f "

func isSchemeChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

// pysplit is urlsplit(url) for a str argument.
func pysplit(url string) (pyURL, error) {
	url = strings.TrimLeft(url, c0OrSpace)
	for _, b := range []string{"\t", "\r", "\n"} {
		url = strings.ReplaceAll(url, b, "")
	}
	var u pyURL
	if i := strings.IndexByte(url, ':'); i > 0 && (url[0] >= 'a' && url[0] <= 'z' || url[0] >= 'A' && url[0] <= 'Z') {
		ok := true
		for j := range i {
			if !isSchemeChar(url[j]) {
				ok = false
				break
			}
		}
		if ok {
			u.scheme, url = strings.ToLower(url[:i]), url[i+1:]
		}
	}
	if strings.HasPrefix(url, "//") {
		end := len(url)
		if i := strings.IndexAny(url[2:], "/?#"); i >= 0 {
			end = i + 2
		}
		u.netloc, url = url[2:end], url[end:]
		open, closed := strings.Contains(u.netloc, "["), strings.Contains(u.netloc, "]")
		if open != closed {
			return pyURL{}, errPyURL
		}
		if open && closed {
			if err := checkBracketedNetloc(u.netloc); err != nil {
				return pyURL{}, err
			}
		}
	}
	if before, after, ok := strings.Cut(url, "#"); ok {
		url, u.fragment = before, after
	}
	if before, after, ok := strings.Cut(url, "?"); ok {
		url, u.query = before, after
	}
	u.path = url
	if err := checkNetloc(u.netloc); err != nil {
		return pyURL{}, err
	}
	return u, nil
}

// nfkcDelimiters are the characters whose NFKC form contains one of
// "/?#@:" (Unicode 17, the database of CPython 3.15); _checknetloc
// refuses a netloc with any of them.
var nfkcDelimiters = []rune{
	0x2047, 0x2048, 0x2049, 0x2100, 0x2101, 0x2105, 0x2106, 0x2A74, 0xFE13, 0xFE16,
	0xFE55, 0xFE56, 0xFE5F, 0xFE6B, 0xFF03, 0xFF0F, 0xFF1A, 0xFF1F, 0xFF20,
}

func checkNetloc(netloc string) error {
	for _, r := range netloc {
		if slices.Contains(nfkcDelimiters, r) {
			return errPyURL
		}
	}
	return nil
}

func checkBracketedNetloc(netloc string) error {
	_, hostPort := rpartition(netloc, "@")
	before, bracketed, open := strings.Cut(hostPort, "[")
	var host string
	if open {
		if before != "" {
			return errPyURL
		}
		var port string
		host, port, _ = strings.Cut(bracketed, "]")
		if port != "" && !strings.HasPrefix(port, ":") {
			return errPyURL
		}
	} else {
		host, _, _ = strings.Cut(hostPort, ":")
	}
	return checkBracketedHost(host)
}

func checkBracketedHost(host string) error {
	if strings.HasPrefix(host, "v") || strings.HasPrefix(host, "V") {
		// \A[vV][a-fA-F0-9]+\..+\z
		rest := host[1:]
		n := 0
		for n < len(rest) && isHex(rest[n]) {
			n++
		}
		if n == 0 || n >= len(rest) || rest[n] != '.' || len(rest) == n+1 {
			return errPyURL
		}
		return nil
	}
	addr, zone, hasZone := strings.Cut(host, "%")
	if hasZone && (zone == "" || strings.Contains(zone, "%")) {
		return errPyURL
	}
	for i := 0; i < len(addr); i++ {
		if c := addr[i]; !isHex(c) && c != ':' && c != '.' {
			return errPyURL
		}
	}
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is6() {
		return errPyURL
	}
	return nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// rpartition is str.rpartition: the parts before and after the last sep,
// or ("", s) without one.
func rpartition(s, sep string) (string, string) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return "", s
}

// userinfo reports whether the netloc has user information (username is
// then never None) and whether it has a password.
func (u pyURL) userinfo() (ok, hasPassword bool) {
	i := strings.LastIndex(u.netloc, "@")
	if i < 0 {
		return false, false
	}
	return true, strings.Contains(u.netloc[:i], ":")
}

func (u pyURL) hostinfo() (host, port string) {
	_, info := rpartition(u.netloc, "@")
	if _, bracketed, open := strings.Cut(info, "["); open {
		var rest string
		host, rest, _ = strings.Cut(bracketed, "]")
		_, port, _ = strings.Cut(rest, ":")
	} else {
		host, port, _ = strings.Cut(info, ":")
	}
	return host, port
}

// hostname is SplitResult.hostname; "" stands for None.
func (u pyURL) hostname() string {
	host, _ := u.hostinfo()
	if host == "" {
		return ""
	}
	name, zone, found := strings.Cut(host, "%")
	if !found {
		return pyLower(name)
	}
	return pyLower(name) + "%" + zone
}

// checkPort raises like SplitResult.port.
func (u pyURL) checkPort() error {
	_, port := u.hostinfo()
	if port == "" {
		return nil
	}
	if !utf8.ValidString(port) {
		return errPyURL
	}
	n := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return errPyURL
		}
		if n = n*10 + int(c-'0'); n > 65535 {
			return errPyURL
		}
	}
	return nil
}

// pyLower is str.lower(): Unicode simple lower case plus the one
// unconditional special casing, U+0130 to "i̇".
func pyLower(s string) string {
	if !strings.ContainsRune(s, 'İ') {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for _, r := range s {
		if r == 'İ' {
			b.WriteString("i̇")
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// pyIsSpace is str.isspace() for one character.
func pyIsSpace(r rune) bool {
	switch r {
	case 0x1c, 0x1d, 0x1e, 0x1f:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r)
}

// pyStrip is str.strip() without arguments.
func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }
