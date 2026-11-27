package sftp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

// router owns the SFTP channel. pkg/sftp talks to the server through it
// (file data: reads with prefetch, concurrent writes, handle attributes),
// and the backend sends its own requests on the same channel (paged
// directory reads, no-follow chmod, the metadata operations with a
// context). Own requests use the ids from ownBase up, pkg/sftp counts from
// one; replies are routed by id.
//
// The router enforces the bounds of the Python release on every reply,
// also on those for pkg/sftp: the packet size (SFTP_MAX_PACKET_BYTES), the
// handle size, names, attribute extensions. A reply that breaks them
// closes the channel. A request without a reply within the operation
// timeout closes the channel as well (the server stalled); everything
// waiting on it fails then.
type router struct {
	ch        io.ReadWriteCloser
	lim       limits
	maxPacket int
	timeout   time.Duration

	wmu sync.Mutex // whole packets on the channel

	// The pipe that carries replies to pkg/sftp.
	libR *io.PipeReader
	libW *io.PipeWriter
	lbuf []byte // partial packet written by pkg/sftp

	mu      sync.Mutex
	own     map[uint32]chan reply
	pending map[uint32]time.Time // every request without a reply
	nextOwn uint32
	ext     map[string]string
	version bool

	ready chan struct{} // VERSION seen
	done  chan struct{}
	once  sync.Once
	err   error
	wg    sync.WaitGroup
}

const ownBase = 1 << 31

// reply is the answer to an own request; body starts after the id.
type reply struct {
	typ  byte
	body []byte
	err  error
}

var (
	errClosed  = errors.New("sftp: channel closed")
	errStalled = errors.New("sftp: server did not answer in time")
)

// transportError is a request whose answer did not arrive. sent tells
// whether it may have reached the server, which makes the outcome of a
// mutation unknown.
type transportError struct {
	sent bool
	err  error
}

func (e *transportError) Error() string { return "sftp transport: " + e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

func newRouter(ch io.ReadWriteCloser, lim limits, maxPacket int, timeout time.Duration) *router {
	r := &router{
		ch: ch, lim: lim, maxPacket: maxPacket, timeout: timeout,
		own: map[uint32]chan reply{}, pending: map[uint32]time.Time{},
		nextOwn: ownBase, ready: make(chan struct{}), done: make(chan struct{}),
	}
	r.libR, r.libW = io.Pipe()
	r.wg.Go(r.readLoop)
	r.wg.Go(r.watchdog)
	return r
}

// fail closes the channel with err; the first error wins.
func (r *router) fail(err error) {
	r.once.Do(func() {
		r.mu.Lock()
		r.err = err
		for id, ch := range r.own {
			ch <- reply{err: err}
			delete(r.own, id)
		}
		r.mu.Unlock()
		close(r.done)
		_ = r.ch.Close()
		_ = r.libW.CloseWithError(err)
		_ = r.libR.CloseWithError(err)
	})
}

// close ends the channel and waits for the router's goroutines.
func (r *router) close() {
	r.fail(errClosed)
	r.wg.Wait()
}

// cause is the error the router failed with, or nil.
func (r *router) cause() error {
	select {
	case <-r.done:
		return r.err
	default:
		return nil
	}
}

func (r *router) extensions() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ext
}

func (r *router) readLoop() {
	head := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r.ch, head); err != nil {
			r.fail(errClosed)
			return
		}
		n := binary.BigEndian.Uint32(head)
		if n == 0 || int64(n) > int64(r.maxPacket) {
			r.fail(errMalformed)
			return
		}
		pkt := make([]byte, 4+n)
		copy(pkt, head)
		if _, err := io.ReadFull(r.ch, pkt[4:]); err != nil {
			r.fail(errClosed)
			return
		}
		if err := r.route(pkt); err != nil {
			r.fail(err)
			return
		}
	}
}

func (r *router) route(pkt []byte) error {
	typ := pkt[4]
	if typ == fxpVersion {
		r.mu.Lock()
		again := r.version
		r.version = true
		r.mu.Unlock()
		if again {
			return errMalformed
		}
		_, ext, err := parseVersion(pkt[5:])
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.ext = ext
		r.mu.Unlock()
		close(r.ready)
		return r.toLib(pkt)
	}
	if len(pkt) < 9 {
		return errMalformed
	}
	id := binary.BigEndian.Uint32(pkt[5:9])
	r.mu.Lock()
	delete(r.pending, id)
	ch, ok := r.own[id]
	delete(r.own, id)
	r.mu.Unlock()
	if id >= ownBase {
		if ok {
			ch <- reply{typ: typ, body: pkt[9:]}
		}
		return nil
	}
	if err := validateReply(typ, pkt[9:], r.lim); err != nil {
		return err
	}
	return r.toLib(pkt)
}

func (r *router) toLib(pkt []byte) error {
	if _, err := r.libW.Write(pkt); err != nil {
		return errClosed
	}
	return nil
}

// watchdog closes the channel when the oldest request waits longer than
// the operation timeout.
func (r *router) watchdog() {
	tick := time.NewTicker(max(r.timeout/10, 50*time.Millisecond))
	defer tick.Stop()
	for {
		select {
		case <-r.done:
			return
		case now := <-tick.C:
			r.mu.Lock()
			stalled := false
			for _, at := range r.pending {
				if now.Sub(at) > r.timeout {
					stalled = true
					break
				}
			}
			r.mu.Unlock()
			if stalled {
				r.fail(errStalled)
				return
			}
		}
	}
}

// lib is the side of the router pkg/sftp reads from and writes to.
type lib struct{ r *router }

func (l lib) Read(p []byte) (int, error) { return l.r.libR.Read(p) }

// Write collects the packets pkg/sftp writes (it writes header and payload
// separately) and sends each whole packet.
func (l lib) Write(p []byte) (int, error) {
	r := l.r
	r.lbuf = append(r.lbuf, p...)
	for len(r.lbuf) >= 4 {
		n := int64(binary.BigEndian.Uint32(r.lbuf))
		if n == 0 || n > int64(r.maxPacket)+1024 {
			r.fail(errMalformed)
			return 0, errMalformed
		}
		if int64(len(r.lbuf)) < 4+n {
			break
		}
		pkt := r.lbuf[:4+n]
		if pkt[4] != fxpInit {
			if n < 5 {
				r.fail(errMalformed)
				return 0, errMalformed
			}
			id := binary.BigEndian.Uint32(pkt[5:9])
			if id >= ownBase {
				r.fail(errMalformed)
				return 0, errMalformed
			}
			r.mu.Lock()
			r.pending[id] = time.Now()
			r.mu.Unlock()
		}
		if err := r.write(pkt); err != nil {
			return 0, err
		}
		r.lbuf = r.lbuf[4+n:]
	}
	if len(r.lbuf) == 0 {
		r.lbuf = r.lbuf[:0:0]
	}
	return len(p), nil
}

// Close is pkg/sftp closing its client: the channel ends with it.
func (l lib) Close() error {
	l.r.fail(errClosed)
	return nil
}

func (r *router) write(pkt []byte) error {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if err := r.cause(); err != nil {
		return err
	}
	if _, err := r.ch.Write(pkt); err != nil {
		r.fail(errClosed)
		return errClosed
	}
	return nil
}

// call sends one own request built by build and waits for its reply, the
// end of ctx or the end of the channel.
func (r *router) call(ctx context.Context, build func(id uint32) *encoder) (reply, error) {
	ch := make(chan reply, 1)
	r.mu.Lock()
	if r.err != nil {
		r.mu.Unlock()
		return reply{}, &transportError{err: r.err}
	}
	id := r.nextOwn
	r.nextOwn++
	if r.nextOwn == 0 {
		r.nextOwn = ownBase
	}
	r.own[id] = ch
	r.pending[id] = time.Now()
	r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		r.forget(id, true)
		return reply{}, &transportError{err: err}
	}
	if err := r.write(build(id).bytes()); err != nil {
		r.forget(id, true)
		return reply{}, &transportError{err: err}
	}
	select {
	case rep := <-ch:
		if rep.err != nil {
			return reply{}, &transportError{sent: true, err: rep.err}
		}
		return rep, nil
	case <-ctx.Done():
		// The server still owes the reply; the watchdog keeps waiting for
		// it, the caller does not.
		r.forget(id, false)
		return reply{}, &transportError{sent: true, err: ctx.Err()}
	}
}

func (r *router) forget(id uint32, unsent bool) {
	r.mu.Lock()
	delete(r.own, id)
	if unsent {
		delete(r.pending, id)
	}
	r.mu.Unlock()
}
