package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestDirectTCPWrite(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := NewTransport(client)

	payload := []byte("hello smb2")

	done := make(chan error, 1)
	var written []byte
	go func() {
		buf := make([]byte, len(payload)+4)
		_, err := io.ReadFull(server, buf)
		written = buf
		done <- err
	}()

	n, err := tr.writev(payload)
	if err != nil {
		t.Fatalf("writev() returned error: %v", err)
	}
	if want := len(payload) + 4; n != want {
		t.Errorf("writev() = %d bytes, want %d", n, want)
	}

	if err := <-done; err != nil {
		t.Fatalf("failed to read written data: %v", err)
	}

	header := binary.BigEndian.Uint32(written[:4])
	if int(header) != len(payload) {
		t.Errorf("NetBIOS header = %d, want %d", header, len(payload))
	}
	if !bytes.Equal(written[4:], payload) {
		t.Errorf("payload = %q, want %q", written[4:], payload)
	}
}

// individualWriteConn wraps a *net.TCPConn and counts individual Write calls.
// It keeps the *net.TCPConn-embedded writeBuffers (writev aggregation) so that
// net.Buffers.WriteTo can still take the aggregated path.
type individualWriteConn struct {
	*net.TCPConn
	writes int
}

func (c *individualWriteConn) Write(p []byte) (int, error) {
	c.writes++
	return c.TCPConn.Write(p)
}

func TestDirectTCPWritevParts(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := NewTransport(client)

	header := []byte("header-part")
	payload := []byte("payload-part")

	done := make(chan error, 1)
	var written []byte
	go func() {
		buf := make([]byte, len(header)+len(payload)+4)
		_, err := io.ReadFull(server, buf)
		written = buf
		done <- err
	}()

	n, err := tr.writev(header, payload)
	if err != nil {
		t.Fatalf("writev() returned error: %v", err)
	}
	if want := len(header) + len(payload) + 4; n != want {
		t.Errorf("writev() = %d bytes, want %d", n, want)
	}

	if err := <-done; err != nil {
		t.Fatalf("failed to read written data: %v", err)
	}

	// the NetBIOS header must cover the concatenated parts
	size := binary.BigEndian.Uint32(written[:4])
	if int(size) != len(header)+len(payload) {
		t.Errorf("NetBIOS header = %d, want %d", size, len(header)+len(payload))
	}
	if !bytes.Equal(written[4:], append(append([]byte{}, header...), payload...)) {
		t.Errorf("written = %q, want %q", written[4:], append(append([]byte{}, header...), payload...))
	}
}

func TestDirectTCPWriteAggregatesHeaderAndPayload(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("failed to accept: %v", err)
		}
		accepted <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	tcpConn := client.(*net.TCPConn)
	conn := &individualWriteConn{TCPConn: tcpConn}
	tr := &transport{conn: conn}

	payload := []byte("hello smb2")

	done := make(chan error, 1)
	var written []byte
	go func() {
		buf := make([]byte, len(payload)+4)
		_, err := io.ReadFull(server, buf)
		written = buf
		done <- err
	}()

	n, err := tr.writev(payload)
	if err != nil {
		t.Fatalf("writev() returned error: %v", err)
	}
	if want := len(payload) + 4; n != want {
		t.Errorf("writev() = %d bytes, want %d", n, want)
	}

	if err := <-done; err != nil {
		t.Fatalf("failed to read written data: %v", err)
	}
	if header := binary.BigEndian.Uint32(written[:4]); int(header) != len(payload) {
		t.Errorf("NetBIOS header = %d, want %d", header, len(payload))
	}
	if !bytes.Equal(written[4:], payload) {
		t.Errorf("payload = %q, want %q", written[4:], payload)
	}

	if conn.writes != 0 {
		t.Errorf("header and payload written with %d individual Write calls, want a single aggregated write", conn.writes)
	}
}

func TestDirectTCPWriteError(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	tr := NewTransport(client)
	server.Close() // close the peer so writes fail

	payload := []byte("hello smb2")
	n, err := tr.writev(payload)
	if err == nil {
		t.Fatal("writev() expected error, got nil")
	}
	if n != -1 {
		t.Errorf("writev() = %d bytes on error, want -1", n)
	}
}

func TestDirectTCPWriteDeadline(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := NewTransport(client)
	tr.setWriteTimeout(10 * time.Millisecond)

	if _, err := tr.writev([]byte("hello smb2")); err == nil {
		t.Fatal("writev() expected deadline error, got nil")
	}
}

// The timeouts bound a stall, not a whole packet: a large packet moving
// steadily on a slow link must not time out.
func TestDirectTCPPacketTimeoutsBoundStalls(t *testing.T) {
	t.Parallel()
	const (
		timeout = time.Second
		piece   = 1 << 20
		pieces  = 4
		pause   = 600 * time.Millisecond // per piece; the packet takes 2.4s
	)
	t.Run("read", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			tr := NewTransport(client)
			defer tr.Close()
			tr.setPacketReadTimeout(timeout)
			go func() {
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], pieces*piece)
				if _, err := server.Write(header[:]); err != nil {
					return
				}
				for range pieces {
					time.Sleep(pause)
					if _, err := server.Write(make([]byte, piece)); err != nil {
						return
					}
				}
			}()
			rp, err := tr.readPacket()
			if err != nil {
				t.Fatalf("readPacket() = %v", err)
			}
			defer rp.close()
			if len(rp.pkt) != pieces*piece {
				t.Fatalf("packet length = %d, want %d", len(rp.pkt), pieces*piece)
			}
		})
	})
	t.Run("write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			tr := NewTransport(client)
			defer tr.Close()
			tr.setWriteTimeout(timeout)
			go func() {
				buf := make([]byte, piece)
				for {
					time.Sleep(pause)
					if _, err := io.ReadFull(server, buf); err != nil {
						return
					}
				}
			}()
			if _, err := tr.writev(make([]byte, pieces*piece)); err != nil {
				t.Fatalf("writev() = %v", err)
			}
		})
	})
}

func TestDirectTCPPacketReadTimeoutDetectsStall(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		tr := NewTransport(client)
		defer tr.Close()
		tr.setPacketReadTimeout(time.Second)
		go func() {
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], 2<<20)
			_, _ = server.Write(header[:])
			_, _ = server.Write(make([]byte, 1<<20))
		}()
		_, err := tr.readPacket()
		var timeoutErr interface{ Timeout() bool }
		if !errors.As(err, &timeoutErr) || !timeoutErr.Timeout() {
			t.Fatalf("readPacket() = %v, want a timeout", err)
		}
	})
}

func TestDirectTCPWriteTooLarge(t *testing.T) {
	t.Parallel()
	_, client := net.Pipe()
	defer client.Close()

	tr := NewTransport(client)

	n, err := tr.writev(make([]byte, maxDirectTCPSize+1))
	if err == nil {
		t.Fatal("writev() expected error, got nil")
	}
	if n != -1 {
		t.Errorf("writev() = %d bytes on error, want -1", n)
	}
}

func TestDirectTCPWriteSumTooLarge(t *testing.T) {
	t.Parallel()
	_, client := net.Pipe()
	defer client.Close()

	tr := NewTransport(client)

	n, err := tr.writev(make([]byte, maxDirectTCPSize), []byte{1})
	if err == nil {
		t.Fatal("writev() expected error, got nil")
	}
	if n != -1 {
		t.Errorf("writev() = %d bytes on error, want -1", n)
	}
}

func TestDirectTCPReadEncryptedPacketReservesAuthenticationTag(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pkt := make([]byte, 128)
	copy(pkt, []byte{0xfd, 'S', 'M', 'B'})
	done := make(chan error, 1)
	go func() {
		wire := make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(wire, uint32(len(pkt)))
		copy(wire[4:], pkt)
		_, err := server.Write(wire)
		done <- err
	}()

	rp, err := NewTransport(client).readPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer rp.close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rp.pkt, pkt) {
		t.Fatal("encrypted packet changed during reception")
	}
	if cap(rp.pkt)-len(rp.pkt) < 16 {
		t.Fatalf("encrypted packet spare capacity = %d, want at least 16", cap(rp.pkt)-len(rp.pkt))
	}
}

type transportReadStep struct {
	data []byte
	err  error
}

type stagedReadConn struct {
	steps         []transportReadStep
	reads         int
	readDeadlines []time.Time
}

func (c *stagedReadConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.steps) == 0 {
		return 0, errors.New("unexpected read after terminal error")
	}

	step := &c.steps[0]
	n := copy(p, step.data)
	if n < len(step.data) {
		step.data = step.data[n:]
		return n, nil
	}
	c.steps = c.steps[1:]
	return n, step.err
}

func (c *stagedReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *stagedReadConn) Close() error                { return nil }
func (c *stagedReadConn) LocalAddr() net.Addr         { return nil }
func (c *stagedReadConn) RemoteAddr() net.Addr        { return nil }
func (c *stagedReadConn) SetDeadline(time.Time) error { return nil }
func (c *stagedReadConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines = append(c.readDeadlines, t)
	return nil
}
func (c *stagedReadConn) SetWriteDeadline(time.Time) error { return nil }

func transportFrame(body []byte) []byte {
	wire := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(wire, uint32(len(body)))
	copy(wire[4:], body)
	return wire
}

func TestDirectTCPReadPacketRetainsDataWithError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "error", err: errors.New("read failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("complete packet")
			conn := &stagedReadConn{steps: []transportReadStep{{data: transportFrame(body), err: tt.err}}}
			tr := NewTransport(conn)

			rp, err := tr.readPacket()
			if err != nil {
				t.Fatalf("readPacket() returned error: %v", err)
			}
			defer rp.close()
			if !bytes.Equal(rp.pkt, body) {
				t.Fatalf("packet = %q, want %q", rp.pkt, body)
			}

			if _, err := tr.readPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("next readPacket() error = %v, want %v", err, tt.err)
			}
			if conn.reads != 1 {
				t.Fatalf("underlying Read calls = %d, want 1", conn.reads)
			}
		})
	}
}

func TestDirectTCPReadPacketRetainsDirectPayloadWithError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "error", err: errors.New("read failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := bytes.Repeat([]byte{'p'}, 100)
			first := make([]byte, 4+80)
			binary.BigEndian.PutUint32(first, uint32(len(body)))
			copy(first[4:], body[:80])
			conn := &stagedReadConn{steps: []transportReadStep{
				{data: first},
				{data: body[80:], err: tt.err},
			}}
			tr := NewTransport(conn)
			sink := make([]byte, len(body)-80)

			rp, err := tr.readPacket(func(head []byte, restSize int) ([]byte, int) {
				if restSize != len(sink) {
					t.Fatalf("restSize = %d, want %d", restSize, len(sink))
				}
				return sink, len(head)
			})
			if err != nil {
				t.Fatalf("readPacket() returned error: %v", err)
			}
			defer rp.close()
			if !bytes.Equal(rp.pkt, body[:80]) {
				t.Fatalf("packet head = %q, want %q", rp.pkt, body[:80])
			}
			if !bytes.Equal(sink, body[80:]) {
				t.Fatalf("direct payload = %q, want %q", sink, body[80:])
			}

			if _, err := tr.readPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("next readPacket() error = %v, want %v", err, tt.err)
			}
			if conn.reads != 2 {
				t.Fatalf("underlying Read calls = %d, want 2", conn.reads)
			}
		})
	}
}

func TestDirectTCPReadPacketRejectsInvalidDirectSinkSize(t *testing.T) {
	t.Parallel()

	body := bytes.Repeat([]byte{0x42}, 120)
	wire := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(wire[:4], uint32(len(body)))
	copy(wire[4:], body)

	tests := []struct {
		name      string
		frontSize int
		sinkLen   int
	}{
		{name: "frontSizeSmallerThanHead", frontSize: 40, sinkLen: 80},
		{name: "frontSizeLargerThanPacket", frontSize: 150, sinkLen: 0},
		{name: "sinkLengthMismatch", frontSize: 80, sinkLen: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &stagedReadConn{steps: []transportReadStep{
				{data: wire},
			}}
			tr := NewTransport(conn)
			sink := make([]byte, tt.sinkLen)
			_, err := tr.readPacket(func(head []byte, restSize int) ([]byte, int) {
				return sink, tt.frontSize
			})
			if err == nil {
				t.Fatal("readPacket() expected error, got nil")
			}
			if !strings.Contains(err.Error(), "invalid direct sink size") {
				t.Fatalf("readPacket() error = %v, want invalid direct sink size", err)
			}
		})
	}
}

func TestDirectTCPReadPacketReturnsBufferedFramesBeforeError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "error", err: errors.New("read failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := []byte("first packet")
			second := []byte("second packet")
			wire := append(transportFrame(first), transportFrame(second)...)
			conn := &stagedReadConn{steps: []transportReadStep{{data: wire, err: tt.err}}}
			tr := NewTransport(conn)

			for _, want := range [][]byte{first, second} {
				rp, err := tr.readPacket()
				if err != nil {
					t.Fatalf("readPacket() returned error: %v", err)
				}
				if !bytes.Equal(rp.pkt, want) {
					t.Fatalf("packet = %q, want %q", rp.pkt, want)
				}
				rp.close()
			}

			if _, err := tr.readPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("final readPacket() error = %v, want %v", err, tt.err)
			}
			if conn.reads != 1 {
				t.Fatalf("underlying Read calls = %d, want 1", conn.reads)
			}
		})
	}
}

func TestDirectTCPReadPacketRejectsIncompleteFrameAfterError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		wire  []byte
		first bool
		err   error
	}{
		{name: "complete then short header EOF", wire: append(transportFrame([]byte("first")), 0, 0), first: true, err: io.EOF},
		{name: "complete then short body EOF", wire: append(transportFrame([]byte("first")), 0, 0, 0, 3, 'a', 'b'), first: true, err: io.EOF},
		{name: "complete then short header error", wire: append(transportFrame([]byte("first")), 0, 0), first: true, err: errors.New("read failed")},
		{name: "complete then short body error", wire: append(transportFrame([]byte("first")), 0, 0, 0, 3, 'a', 'b'), first: true, err: errors.New("read failed")},
		{name: "short header EOF", wire: []byte{0, 0}, err: io.EOF},
		{name: "short body EOF", wire: []byte{0, 0, 0, 3, 'a', 'b'}, err: io.EOF},
		{name: "short header error", wire: []byte{0, 0}, err: errors.New("read failed")},
		{name: "short body error", wire: []byte{0, 0, 0, 3, 'a', 'b'}, err: errors.New("read failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &stagedReadConn{steps: []transportReadStep{{data: tt.wire, err: tt.err}}}
			tr := NewTransport(conn)
			if tt.first {
				rp, err := tr.readPacket()
				if err != nil {
					t.Fatalf("complete frame: %v", err)
				}
				if !bytes.Equal(rp.pkt, []byte("first")) {
					t.Errorf("complete frame = %q", rp.pkt)
				}
				rp.close()
			}

			if _, err := tr.readPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("readPacket() error = %v, want %v", err, tt.err)
			}
			if _, err := tr.readPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("next readPacket() error = %v, want %v", err, tt.err)
			}
			if conn.reads != 1 {
				t.Fatalf("underlying Read calls = %d, want 1", conn.reads)
			}
		})
	}
}

func TestDirectTCPReadPacketSetsDeadlineForIncompleteFrame(t *testing.T) {
	t.Parallel()
	t.Run("incomplete frame sets and clears deadline", func(t *testing.T) {
		conn := &stagedReadConn{
			steps: []transportReadStep{
				{data: []byte{0, 0, 0, 10}},
				{data: []byte("0123456789")},
			},
		}
		tr := NewTransport(conn)
		rp, err := tr.readPacket()
		if err != nil {
			t.Fatalf("readPacket() error: %v", err)
		}
		rp.close()

		if len(conn.readDeadlines) != 2 {
			t.Fatalf("readDeadlines calls = %d, want 2", len(conn.readDeadlines))
		}
		if conn.readDeadlines[0].IsZero() {
			t.Errorf("initial deadline was zero, want non-zero")
		}
		if !conn.readDeadlines[1].IsZero() {
			t.Errorf("final deadline was non-zero, want zero")
		}
	})

	t.Run("already buffered frame skips deadline", func(t *testing.T) {
		conn := &stagedReadConn{
			steps: []transportReadStep{
				{data: transportFrame([]byte("hello"))},
			},
		}
		tr := NewTransport(conn)
		rp, err := tr.readPacket()
		if err != nil {
			t.Fatalf("readPacket() error: %v", err)
		}
		rp.close()

		if len(conn.readDeadlines) != 0 {
			t.Errorf("readDeadlines calls = %d, want 0", len(conn.readDeadlines))
		}
	})

	t.Run("custom read timeout applies", func(t *testing.T) {
		conn := &stagedReadConn{
			steps: []transportReadStep{
				{data: []byte{0, 0, 0, 10}},
				{data: []byte("0123456789")},
			},
		}
		dt := NewTransport(conn)
		dt.setPacketReadTimeout(5 * time.Second)
		start := time.Now()
		rp, err := dt.readPacket()
		if err != nil {
			t.Fatalf("readPacket() error: %v", err)
		}
		rp.close()

		if len(conn.readDeadlines) != 2 {
			t.Fatalf("readDeadlines calls = %d, want 2", len(conn.readDeadlines))
		}
		deadline := conn.readDeadlines[0]
		if deadline.Before(start.Add(4*time.Second)) || deadline.After(start.Add(6*time.Second)) {
			t.Errorf("deadline = %v, expected ~5s from %v", deadline, start)
		}
	})
}
