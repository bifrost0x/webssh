package hostops

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// fakeProber answers each "host:port" with a scripted behaviour:
//
//	"ssh:<greeting>"  accepts and sends the greeting, then waits
//	"text:<data>"     accepts and sends data that is no SSH greeting
//	"silent"          accepts and sends nothing
//	"blocked"         the network policy refuses the address
//	"unresolved"      the name does not resolve
//	"hold"            blocks until release is closed or ctx ends
//	anything else     the connection is refused
type fakeProber struct {
	mu       sync.Mutex
	script   map[string]string
	release  chan struct{}
	dialed   []string
	written  atomic.Int64
	inFlight atomic.Int64
	peak     atomic.Int64
}

func (f *fakeProber) DialProbe(ctx context.Context, host string, port int) (Conn, error) {
	key := net.JoinHostPort(host, strconv.Itoa(port))
	f.mu.Lock()
	f.dialed = append(f.dialed, key)
	how := f.script[key]
	f.mu.Unlock()
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	switch {
	case how == "blocked":
		return nil, fault.New(fault.TargetBlocked, "Connections to this address are not allowed.")
	case how == "unresolved":
		return nil, fault.New(fault.Unreachable, "Host could not be resolved.")
	case how == "hold":
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return nil, errors.New("refused")
	case len(how) > 4 && how[:4] == "ssh:", len(how) > 5 && how[:5] == "text:", how == "silent":
		client, server := net.Pipe()
		go f.serve(server, how)
		return client, nil
	}
	return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
}

func (f *fakeProber) serve(conn net.Conn, how string) {
	defer conn.Close()
	data := ""
	switch {
	case how[:4] == "ssh:":
		data = how[4:]
	case how[:5] == "text:":
		data = how[5:]
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if data != "" {
		if _, err := conn.Write([]byte(data)); err != nil {
			return
		}
	}
	// The probe never sends anything; count what arrives until it closes.
	buf := make([]byte, 64)
	for {
		n, err := conn.Read(buf)
		f.written.Add(int64(n))
		if err != nil {
			return
		}
	}
}

func (f *fakeProber) dials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

type discoveryAudit struct {
	mu     sync.Mutex
	events []string
}

func (a *discoveryAudit) Security(event string, _ ...any) {
	a.mu.Lock()
	a.events = append(a.events, event)
	a.mu.Unlock()
}

func (a *discoveryAudit) all() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.events...)
}

type fakeLimiter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (l *fakeLimiter) Allow(key string, limit int, _ time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts == nil {
		l.counts = map[string]int{}
	}
	if l.counts[key] >= limit {
		return false
	}
	l.counts[key]++
	return true
}
