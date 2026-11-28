package ldap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/ldapproto"
)

var (
	// ErrUnavailable means the directory gave no verdict: unreachable,
	// misconfigured, a protocol or TLS failure, a refused service account.
	// It never counts as a wrong password; callers fail closed.
	ErrUnavailable = errors.New("ldap: directory unavailable")
	// ErrRejected means the lookup did not resolve to exactly one usable
	// identity.
	ErrRejected = errors.New("ldap: lookup rejected")
)

// Limits of app/ldap_service.py, in code points.
const (
	maxUsernameRunes = 256
	maxDNRunes       = 2048
	placeholder      = "{username}"
	searchSizeLimit  = 2
)

// Settings are the directory settings (config.LDAP). internal/config has
// validated them like the Python release.
type Settings struct {
	Provider          string // LDAP_PROVIDER_ID
	URL               string // LDAP_URL
	BackupURL         string // LDAP_BACKUP_URL, optional
	BaseDN            string
	BindDN            string
	BindPasswordFile  string
	CAFile            string
	UserFilter        string // with exactly one {username}
	UniqueIDAttribute string
	ConnectTimeout    time.Duration // connect, TLS and bind
	OperationTimeout  time.Duration // the search
	// Dial opens the TCP connection; nil uses a net.Dialer. The lab tests
	// use it to reach the directories by their in-network names.
	Dial ldapproto.DialFunc
}

// Entry is the directory entry of a user: the canonical unique attribute
// (the subject of the identity) and its distinguished name. LegacySubject
// is the ambiguous subject the Python release stored for the same value
// (Subjects), "" when there is none.
type Entry struct {
	Subject       string
	DN            string
	LegacySubject string
}

// matches reports whether id is the identity of e: bound to its subject,
// or to its ambiguous Python subject (LegacySubject) and recorded for
// the same distinguished name.
func (e Entry) matches(id Identity) bool {
	if id.Subject == e.Subject {
		return true
	}
	return e.LegacySubject != "" && id.Subject == e.LegacySubject && strings.EqualFold(id.DistinguishedName, e.DN)
}

// Client talks to the directory: the service account searches, the user's
// own simple bind proves the password. It keeps no credentials of users
// and reads the service password for every search. It is safe for
// concurrent use.
type Client struct {
	s         Settings
	endpoints []ldapproto.ServerURL

	mu     sync.Mutex
	active int // index of the endpoint that answered last
}

// NewClient parses the server URLs. A filter that does not compile is not
// an error here: Ready reports it, so that the server starts and only LDAP
// is not ready (condition K7/A2).
func NewClient(s Settings) (*Client, error) {
	primary, err := ldapproto.ParseServerURL(s.URL)
	if err != nil {
		return nil, fmt.Errorf("LDAP_URL: %w", err)
	}
	c := &Client{s: s, endpoints: []ldapproto.ServerURL{primary}}
	if s.BackupURL != "" {
		backup, err := ldapproto.ParseServerURL(s.BackupURL)
		if err != nil {
			return nil, fmt.Errorf("LDAP_BACKUP_URL: %w", err)
		}
		c.endpoints = append(c.endpoints, backup)
	}
	if s.ConnectTimeout <= 0 || s.OperationTimeout <= 0 {
		return nil, errors.New("ldap: timeouts must be positive")
	}
	return c, nil
}

// Ready checks what start-up can check without the network: the bind
// password file and the CA bundle are usable (validate_runtime_files) and
// the filter template compiles with a plain user name.
func (c *Client) Ready() error {
	if _, err := readSecret(c.s.BindPasswordFile); err != nil {
		return err
	}
	if _, err := loadCA(c.s.CAFile); err != nil {
		return err
	}
	if _, err := ldapproto.CompileFilter(strings.Replace(c.s.UserFilter, placeholder, "user", 1)); err != nil {
		return fmt.Errorf("%w: LDAP_USER_FILTER: %w", ErrUnavailable, err)
	}
	return nil
}

// Transport is "ldap+StartTLS" or "ldaps" for LDAP_URL, as the status
// route shows it.
func (c *Client) Transport() string {
	if c.endpoints[0].Scheme == "ldap" {
		return "ldap+StartTLS"
	}
	return "ldaps"
}

// order returns the endpoints with the one that answered last first.
func (c *Client) order() []int {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	out := []int{active}
	for i := range c.endpoints {
		if i != active {
			out = append(out, i)
		}
	}
	return out
}

// withFailover runs op against each endpoint until one gives a verdict,
// that is anything but ErrUnavailable (_with_failover).
func withFailover[T any](c *Client, op func(ldapproto.ServerURL) (T, error)) (T, error) {
	var errs []error
	for _, i := range c.order() {
		v, err := op(c.endpoints[i])
		if err == nil || !errors.Is(err, ErrUnavailable) {
			if err == nil {
				c.mu.Lock()
				c.active = i
				c.mu.Unlock()
			}
			return v, err
		}
		errs = append(errs, err)
	}
	var zero T
	return zero, fmt.Errorf("%w: LDAP servers are unavailable: %w", ErrUnavailable, errors.Join(errs...))
}

// connect dials, secures and binds within LDAP_CONNECT_TIMEOUT, which in
// the Python release covered the bind as well. A wrong password is
// ldapproto.ErrInvalidCredentials; everything else is ErrUnavailable.
func (c *Client) connect(ctx context.Context, url ldapproto.ServerURL, dn, password string) (*ldapproto.Conn, error) {
	pool, err := loadCA(c.s.CAFile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeoutCause(ctx, c.s.ConnectTimeout, errors.New("ldap connect timeout"))
	defer cancel()
	conn, err := ldapproto.Dial(ctx, ldapproto.Config{URL: url, RootCAs: pool, Dial: c.s.Dial})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if err := conn.Bind(ctx, dn, password); err != nil {
		_ = conn.Close()
		if errors.Is(err, ldapproto.ErrInvalidCredentials) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: bind: %w", ErrUnavailable, err)
	}
	return conn, nil
}

// Lookup finds exactly one entry for username with the service account
// (LDAPDirectory.lookup). The name is stripped like Python's str.strip;
// an empty name or one longer than 256 characters is ErrRejected.
func (c *Client) Lookup(ctx context.Context, username string) (Entry, error) {
	username = strings.TrimFunc(username, pyIsSpace)
	if username == "" || !utf8.ValidString(username) || utf8.RuneCountInString(username) > maxUsernameRunes {
		return Entry{}, fmt.Errorf("%w: username is invalid", ErrRejected)
	}
	filter, err := ldapproto.CompileFilter(strings.Replace(c.s.UserFilter, placeholder, ldapproto.EscapeFilterValue(username), 1))
	if err != nil {
		// libldap refuses the filter before anything is sent; Bonsai's
		// FilterError made the Python release report the directory as
		// unavailable.
		return Entry{}, fmt.Errorf("%w: LDAP_USER_FILTER: %w", ErrUnavailable, err)
	}
	password, err := readSecret(c.s.BindPasswordFile)
	if err != nil {
		return Entry{}, err
	}
	found, err := withFailover(c, func(url ldapproto.ServerURL) ([]Entry, error) {
		return c.search(ctx, url, filter, password)
	})
	if err != nil {
		return Entry{}, err
	}
	if len(found) != 1 {
		return Entry{}, fmt.Errorf("%w: lookup returned %d identities", ErrRejected, len(found))
	}
	return found[0], nil
}

func (c *Client) search(ctx context.Context, url ldapproto.ServerURL, filter []byte, password string) ([]Entry, error) {
	conn, err := c.connect(ctx, url, c.s.BindDN, password)
	if errors.Is(err, ldapproto.ErrInvalidCredentials) {
		return nil, fmt.Errorf("%w: the service account bind was refused", ErrUnavailable)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	opCtx, cancel := context.WithTimeoutCause(ctx, c.s.OperationTimeout, errors.New("ldap operation timeout"))
	defer cancel()
	res, err := conn.Search(opCtx, ldapproto.SearchRequest{
		BaseDN: c.s.BaseDN, Scope: ldapproto.ScopeSubtree, SizeLimit: searchSizeLimit,
		TimeLimit: int(c.s.OperationTimeout / time.Second), Filter: filter, Attributes: []string{c.s.UniqueIDAttribute},
	})
	switch {
	case errors.Is(err, ldapproto.ErrSizeLimit):
		// More entries than the size limit: as ambiguous as two entries.
		return nil, fmt.Errorf("%w: more than one entry matched", ErrRejected)
	case err != nil:
		// A referral for the base itself lands here as well: the search
		// cannot decide, so the directory counts as unavailable.
		return nil, fmt.Errorf("%w: search: %w", ErrUnavailable, err)
	}
	// Continuation references are never followed, as in the Python
	// release (set_ignore_referrals); following one would send the service
	// password to a server the directory names.
	out := make([]Entry, 0, len(res.Entries))
	for _, e := range res.Entries {
		entry, err := c.entry(e)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func (c *Client) entry(e ldapproto.Entry) (Entry, error) {
	values := e.Values(c.s.UniqueIDAttribute)
	if len(values) != 1 {
		return Entry{}, fmt.Errorf("%w: identity attribute must have exactly one value", ErrRejected)
	}
	subject, legacy, err := Subjects(values[0])
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	dn := strings.TrimFunc(e.DN, pyIsSpace)
	if dn == "" || utf8.RuneCountInString(dn) > maxDNRunes || strings.ContainsRune(dn, 0) {
		return Entry{}, fmt.Errorf("%w: distinguished name is invalid", ErrRejected)
	}
	return Entry{Subject: subject, DN: dn, LegacySubject: legacy}, nil
}

// VerifyPassword binds as dn. A wrong password is false; a directory that
// gives no verdict is ErrUnavailable. An empty password is false without
// asking the directory: servers treat it as an unauthenticated bind.
func (c *Client) VerifyPassword(ctx context.Context, dn, password string) (bool, error) {
	if password == "" {
		return false, nil
	}
	return withFailover(c, func(url ldapproto.ServerURL) (bool, error) {
		conn, err := c.connect(ctx, url, dn, password)
		if errors.Is(err, ldapproto.ErrInvalidCredentials) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		_ = conn.Close()
		return true, nil
	})
}

// Probe binds the service account (the readiness check of the status
// route).
func (c *Client) Probe(ctx context.Context) error {
	password, err := readSecret(c.s.BindPasswordFile)
	if err != nil {
		return err
	}
	_, err = withFailover(c, func(url ldapproto.ServerURL) (struct{}, error) {
		conn, err := c.connect(ctx, url, c.s.BindDN, password)
		if errors.Is(err, ldapproto.ErrInvalidCredentials) {
			return struct{}{}, fmt.Errorf("%w: the service account bind was refused", ErrUnavailable)
		}
		if err != nil {
			return struct{}{}, err
		}
		_ = conn.Close()
		return struct{}{}, nil
	})
	return err
}
