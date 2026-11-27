package httpapi

import (
	"net"
	"sync"
)

// MaxConnections bounds the HTTP connections the server holds at once,
// realtime connections included. The Python release had no setting for
// it (Gunicorn's gthread worker held at most 1000 connections); the bound
// is generous so that no existing installation reaches it, and keeps a
// flood of idle or slow connections from exhausting file descriptors and
// memory. Beyond it new connections wait in the listen backlog until one
// closes.
const MaxConnections = 4096

// LimitListener returns a listener that holds at most n accepted
// connections at once; Accept waits while n are open.
func LimitListener(ln net.Listener, n int) net.Listener {
	return &limitListener{Listener: ln, slots: make(chan struct{}, n), done: make(chan struct{})}
}

type limitListener struct {
	net.Listener
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
}

func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

// limitConn frees its slot on the first Close.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// CloseWrite passes the half close through: net/http uses it to send the
// answer to a request whose body it did not read before it closes the
// connection, so the client is not reset before it reads the answer.
func (c *limitConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
