package ldapproto

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ErrURL reports an LDAP URL that is not usable as a server address.
var ErrURL = errors.New("ldap: invalid server URL")

// ServerURL is a parsed ldap:// or ldaps:// server address (RFC 4516).
type ServerURL struct {
	Scheme string
	Host   string
	Port   int
}

// Address returns host:port for dialing.
func (u ServerURL) Address() string { return net.JoinHostPort(u.Host, strconv.Itoa(u.Port)) }

// String formats the URL.
func (u ServerURL) String() string { return u.Scheme + "://" + u.Address() }

// ParseServerURL parses a configured server URL (LDAP_URL,
// LDAP_BACKUP_URL). Like the configuration check of the Python release it
// refuses user info, path, query and fragment; internal/config has
// already applied that check with Python's URL parser.
func ParseServerURL(raw string) (ServerURL, error) {
	if len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r\n") {
		return ServerURL{}, ErrURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ServerURL{}, fmt.Errorf("%w: %w", ErrURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	defaultPort := 389
	switch scheme {
	case "ldap":
	case "ldaps":
		defaultPort = 636
	default:
		return ServerURL{}, fmt.Errorf("%w: scheme", ErrURL)
	}
	host := u.Hostname()
	if host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return ServerURL{}, fmt.Errorf("%w: host or user info", ErrURL)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Path != "" || u.RawPath != "" {
		return ServerURL{}, fmt.Errorf("%w: path or query", ErrURL)
	}
	port := defaultPort
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return ServerURL{}, fmt.Errorf("%w: port", ErrURL)
		}
	}
	return ServerURL{Scheme: scheme, Host: strings.ToLower(strings.TrimSuffix(host, ".")), Port: port}, nil
}
