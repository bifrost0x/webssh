package ldapproto

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// DialFunc opens the TCP connection; tests use it to reach lab hosts by
// their in-network names.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config describes how to reach and trust one directory server.
type Config struct {
	URL     ServerURL
	RootCAs *x509.CertPool // only these anchors are trusted; never the system pool
	Dial    DialFunc       // optional, defaults to net.Dialer
}

// Conn is one TLS-protected LDAP connection. Operations are sequential;
// a failed or cancelled operation closes the connection.
type Conn struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
	nextID int64
	broken bool
}

// Dial connects and secures the connection: ldaps:// with implicit TLS,
// ldap:// with StartTLS before any other operation. ctx bounds the whole
// setup including the TLS handshake.
func Dial(ctx context.Context, cfg Config) (*Conn, error) {
	if cfg.RootCAs == nil {
		return nil, errors.New("ldap: a CA pool is required")
	}
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	raw, err := dial(ctx, "tcp", cfg.URL.Address())
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %s: %w", cfg.URL, err)
	}
	c := &Conn{conn: raw, reader: bufio.NewReader(raw), nextID: 1}
	stop := c.watch(ctx)
	defer stop()
	if cfg.URL.Scheme == "ldap" {
		if err := c.startTLS(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	tlsConn := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    cfg.RootCAs,
		ServerName: cfg.URL.Host,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("ldap: tls handshake with %s: %w", cfg.URL, contextCause(ctx, err))
	}
	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	return c, nil
}

// watch applies the context deadline to the socket and interrupts blocked
// reads on cancellation. The returned function must be called afterwards.
func (c *Conn) watch(ctx context.Context) func() {
	conn := c.conn
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stop()
		_ = conn.SetDeadline(time.Time{})
	}
}

// contextCause attributes a socket error to the context when the context
// ended. The socket deadline equals the context deadline, so the read can
// fail an instant before ctx.Err is set; a passed deadline counts as well.
func contextCause(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w (%w)", context.Cause(ctx), err)
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) && errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("%w (%w)", context.DeadlineExceeded, err)
	}
	return err
}

func (c *Conn) startTLS(ctx context.Context) error {
	id := c.nextID
	c.nextID++
	if _, err := c.conn.Write(envelope(id, startTLSRequest())); err != nil {
		return fmt.Errorf("%w: %w", ErrStartTLS, contextCause(ctx, err))
	}
	msg, err := c.read(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStartTLS, err)
	}
	if msg.id != id || msg.op.tag != opExtendedResponse {
		return fmt.Errorf("%w: unexpected response", ErrStartTLS)
	}
	res, _, err := parseResult(msg.op)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStartTLS, err)
	}
	if res.Code != ResultSuccess {
		return fmt.Errorf("%w: %w", ErrStartTLS, &ResultError{Op: "starttls", Result: res})
	}
	if c.reader.Buffered() != 0 {
		return fmt.Errorf("%w: data after response", ErrStartTLS)
	}
	return nil
}

func (c *Conn) read(ctx context.Context) (message, error) {
	raw, err := readMessage(c.reader, maxSearchSize)
	if err != nil {
		return message{}, contextCause(ctx, err)
	}
	msg, err := parseMessage(raw)
	if err != nil {
		return message{}, err
	}
	if msg.id == 0 {
		return message{}, fmt.Errorf("%w: server sent notice of disconnection", ErrConnClosed)
	}
	return msg, nil
}

// begin locks the connection for one operation.
func (c *Conn) begin(ctx context.Context) (int64, func(error) error, error) {
	c.mu.Lock()
	if c.broken {
		c.mu.Unlock()
		return 0, nil, ErrConnClosed
	}
	stop := c.watch(ctx)
	id := c.nextID
	c.nextID++
	finish := func(err error) error {
		stop()
		var resErr *ResultError
		var refErr *ReferralError
		if err != nil && !errors.Is(err, ErrInvalidCredentials) && !errors.Is(err, ErrSizeLimit) &&
			!errors.As(err, &resErr) && !errors.As(err, &refErr) {
			c.broken = true
			_ = c.conn.Close()
		}
		c.mu.Unlock()
		return err
	}
	return id, finish, nil
}

// Bind performs a simple bind. Empty DN or password is refused locally,
// because servers treat it as an unauthenticated bind that "succeeds".
func (c *Conn) Bind(ctx context.Context, dn, password string) error {
	if dn == "" || password == "" {
		return ErrEmptyPassword
	}
	id, finish, err := c.begin(ctx)
	if err != nil {
		return err
	}
	return finish(c.bind(ctx, id, dn, password))
}

func (c *Conn) bind(ctx context.Context, id int64, dn, password string) error {
	if _, err := c.conn.Write(envelope(id, bindRequest(dn, password))); err != nil {
		return contextCause(ctx, err)
	}
	msg, err := c.read(ctx)
	if err != nil {
		return err
	}
	if msg.id != id || msg.op.tag != opBindResponse {
		return fmt.Errorf("%w: unexpected bind response", ErrMalformed)
	}
	res, _, err := parseResult(msg.op)
	switch {
	case err != nil:
		return err
	case res.Code == ResultSuccess:
		return nil
	case res.Code == ResultInvalidCredentials:
		return ErrInvalidCredentials
	case res.Code == ResultReferral:
		return &ReferralError{URLs: res.Referrals}
	default:
		return &ResultError{Op: "bind", Result: res}
	}
}

// SearchResult holds entries and unfollowed continuation references.
type SearchResult struct {
	Entries    []Entry
	References []string
}

// Search runs one search and collects its results. The size limit is also
// enforced on the client, so a server ignoring it cannot flood memory.
func (c *Conn) Search(ctx context.Context, req SearchRequest) (SearchResult, error) {
	if req.SizeLimit <= 0 {
		return SearchResult{}, errors.New("ldap: a positive size limit is required")
	}
	id, finish, err := c.begin(ctx)
	if err != nil {
		return SearchResult{}, err
	}
	res, err := c.search(ctx, id, req)
	return res, finish(err)
}

func (c *Conn) search(ctx context.Context, id int64, req SearchRequest) (SearchResult, error) {
	var out SearchResult
	if _, err := c.conn.Write(envelope(id, req.encode())); err != nil {
		return out, contextCause(ctx, err)
	}
	refBytes := 0
	for others := 0; ; {
		msg, err := c.read(ctx)
		if err != nil {
			return out, err
		}
		if msg.id != id {
			return out, fmt.Errorf("%w: response for unknown message %d", ErrMalformed, msg.id)
		}
		if msg.op.tag != opSearchEntry {
			if others++; others > maxSearchOtherMessages {
				c.broken = true
				_ = c.conn.Close()
				return out, fmt.Errorf("%w: too many messages in one search", ErrMalformed)
			}
		}
		switch msg.op.tag {
		case opSearchEntry:
			entry, err := parseEntry(msg.op)
			if err != nil {
				return out, err
			}
			if len(out.Entries) >= req.SizeLimit {
				// The server ignored the limit; the rest of the stream is
				// unread, so the connection cannot be reused.
				c.broken = true
				_ = c.conn.Close()
				return out, ErrSizeLimit
			}
			out.Entries = append(out.Entries, entry)
		case opSearchReference:
			refs, err := parseURIs(msg.op)
			if err != nil {
				return out, err
			}
			// References are never followed; only a bounded number is
			// kept for diagnostics.
			for _, ref := range refs {
				if len(out.References) < maxReferences && refBytes+len(ref) <= maxReferenceBytes {
					out.References = append(out.References, ref)
					refBytes += len(ref)
				}
			}
		case opIntermediate:
		case opSearchDone:
			return out, searchDone(msg.op)
		default:
			return out, fmt.Errorf("%w: unexpected operation 0x%02x", ErrMalformed, msg.op.tag)
		}
	}
}

func searchDone(op element) error {
	res, _, err := parseResult(op)
	switch {
	case err != nil:
		return err
	case res.Code == ResultSuccess:
		return nil
	case res.Code == ResultSizeLimitExceeded:
		return ErrSizeLimit
	case res.Code == ResultReferral:
		return &ReferralError{URLs: res.Referrals}
	default:
		return &ResultError{Op: "search", Result: res}
	}
}

// Close sends an unbind and closes the socket.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken {
		return nil
	}
	c.broken = true
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = c.conn.Write(envelope(c.nextID, unbindRequest()))
	return c.conn.Close()
}

// Values returns the values of an attribute; names compare case-insensitively.
func (e Entry) Values(name string) [][]byte {
	var out [][]byte
	for k, v := range e.Attributes {
		if strings.EqualFold(k, name) {
			out = append(out, v...)
		}
	}
	return out
}
