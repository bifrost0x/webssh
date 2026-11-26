package config

import (
	"errors"
	"strings"
)

// pyURL is the result of Python's urllib.parse.urlsplit for a str, with
// the netloc properties the Python release reads. A missing netloc, query
// or fragment is the empty string, as in Python's default mode.
type pyURL struct {
	scheme, netloc, path, query, fragment string
}

var errPyURL = errors.New("invalid URL")

// nfkcURLDelimiters lists the code points whose NFKC form contains one of
// "/?#@:" (Unicode 17, the version of both Python 3.15 and the Go
// toolchain). urlsplit rejects a non-ASCII netloc that contains one of
// them (_checknetloc); NFKC composition never creates these ASCII
// characters, so a check per code point is exact.
var nfkcURLDelimiters = map[rune]bool{
	0x2047: true, 0x2048: true, 0x2049: true, 0x2100: true, 0x2101: true,
	0x2105: true, 0x2106: true, 0x2A74: true, 0xFE13: true, 0xFE16: true,
	0xFE55: true, 0xFE56: true, 0xFE5F: true, 0xFE6B: true, 0xFF03: true,
	0xFF0F: true, 0xFF1A: true, 0xFF1F: true, 0xFF20: true,
}

const urlSchemeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."

// pyURLSplit is urlsplit(url) of Python 3.15. It fails where urlsplit
// raises ValueError.
func pyURLSplit(url string) (pyURL, error) {
	url = strings.TrimLeft(url, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ")
	url = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(url)
	var u pyURL
	if i := strings.IndexByte(url, ':'); i > 0 && isASCIILetter(url[0]) {
		scheme := url[:i]
		if strings.Trim(scheme, urlSchemeChars) == "" {
			u.scheme, url = strings.ToLower(scheme), url[i+1:]
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
		if open {
			if err := checkBracketedNetloc(u.netloc); err != nil {
				return pyURL{}, err
			}
		}
	}
	if before, after, found := strings.Cut(url, "#"); found {
		url, u.fragment = before, after
	}
	if before, after, found := strings.Cut(url, "?"); found {
		url, u.query = before, after
	}
	u.path = url
	if !isASCII(u.netloc) {
		for _, r := range u.netloc {
			if nfkcURLDelimiters[r] {
				return pyURL{}, errPyURL
			}
		}
	}
	return u, nil
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func checkBracketedNetloc(netloc string) error {
	hostPort := netloc[strings.LastIndexByte(netloc, '@')+1:]
	var host string
	if before, bracketed, found := strings.Cut(hostPort, "["); found {
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
	if strings.HasPrefix(host, "v") || strings.HasPrefix(host, "V") {
		if !ipvFuture(host) {
			return errPyURL
		}
		return nil
	}
	a, err := pyIPAddress(host)
	if err != nil || a.is4 {
		return errPyURL
	}
	return nil
}

// ipvFuture matches \A[vV][a-fA-F0-9]+\..+\z.
func ipvFuture(host string) bool {
	rest := host[1:]
	i := 0
	for i < len(rest) && isHexDigit(rest[i]) {
		i++
	}
	// "." in the pattern does not match a line feed.
	return i > 0 && i+1 < len(rest) && rest[i] == '.' && !strings.Contains(rest[i+1:], "\n")
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// userinfo returns username and password; ok reports whether netloc has
// an "@" (username is None in Python otherwise), hasPassword whether the
// user info has a ":".
func (u pyURL) userinfo() (username string, hasUser bool, password string, hasPassword bool) {
	i := strings.LastIndexByte(u.netloc, '@')
	if i < 0 {
		return "", false, "", false
	}
	username, password, hasPassword = strings.Cut(u.netloc[:i], ":")
	return username, true, password, hasPassword
}

// hasCredentials reports username is not None or password is not None.
func (u pyURL) hasCredentials() bool {
	_, hasUser, _, _ := u.userinfo()
	return hasUser
}

func (u pyURL) hostinfo() (host, port string) {
	hostinfo := u.netloc[strings.LastIndexByte(u.netloc, '@')+1:]
	if _, bracketed, found := strings.Cut(hostinfo, "["); found {
		var rest string
		host, rest, _ = strings.Cut(bracketed, "]")
		_, port, _ = strings.Cut(rest, ":")
		return host, port
	}
	host, port, _ = strings.Cut(hostinfo, ":")
	return host, port
}

// hostname is the hostname property: lower case except an IPv6 zone, and
// "" where Python returns None.
func (u pyURL) hostname() string {
	host, _ := u.hostinfo()
	if host == "" {
		return ""
	}
	name, zone, found := strings.Cut(host, "%")
	if !found {
		return pyLower(host)
	}
	return pyLower(name) + "%" + zone
}

// port is the port property: -1 when absent, an error where Python raises.
func (u pyURL) port() (int, error) {
	_, raw := u.hostinfo()
	if raw == "" {
		return -1, nil
	}
	if !isASCIIDigits(raw) {
		return 0, errPyURL
	}
	v, _ := pyInt(raw)
	if !v.IsInt64() || v.Int64() > 65535 {
		return 0, errPyURL
	}
	return int(v.Int64()), nil
}
