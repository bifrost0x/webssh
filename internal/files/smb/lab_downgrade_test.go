package smb

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
)

// tamperConn rewrites the first SMB frame the server sends (the NEGOTIATE
// response) before the client sees it.
type tamperConn struct {
	net.Conn
	once sync.Once
	edit func(frame []byte) bool
	buf  []byte
	err  error
	hit  bool
}

func (c *tamperConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		var hdr [4]byte
		if _, c.err = io.ReadFull(c.Conn, hdr[:]); c.err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(hdr[:]) & 0xffffff)
		frame := make([]byte, n)
		if _, c.err = io.ReadFull(c.Conn, frame); c.err != nil {
			return
		}
		c.hit = c.edit(frame)
		c.buf = append(hdr[:], frame...)
	})
	if c.err != nil {
		return 0, c.err
	}
	if len(c.buf) > 0 {
		k := copy(p, c.buf)
		c.buf = c.buf[k:]
		return k, nil
	}
	return c.Conn.Read(p)
}

const smbHeader = 64

// encryptionContext returns the offset of the cipher id chosen in the
// NEGOTIATE response's SMB2_ENCRYPTION_CAPABILITIES context.
func encryptionContext(frame []byte) int {
	body := frame[smbHeader:]
	count := int(binary.LittleEndian.Uint16(body[6:8]))
	off := int(binary.LittleEndian.Uint32(body[60:64]))
	for range count {
		off = (off + 7) &^ 7
		if off+8 > len(frame) {
			return -1
		}
		typ := binary.LittleEndian.Uint16(frame[off:])
		ln := int(binary.LittleEndian.Uint16(frame[off+2:]))
		if typ == 2 {
			return off + 8 + 2 // CipherCount, then the chosen cipher
		}
		off += 8 + ln
	}
	return -1
}

// A man in the middle that rewrites the NEGOTIATE response must never get
// a session: a lower dialect, a weaker cipher or a cleared signing bit.
func TestLabNegotiateTamperingIsRefused(t *testing.T) {
	for _, tg := range labTargets(t) {
		if tg.windows {
			continue
		}
		for _, c := range []struct {
			name string
			edit func([]byte) bool
		}{
			{"dialect 3.0.2", func(f []byte) bool { binary.LittleEndian.PutUint16(f[smbHeader+4:], 0x0302); return true }},
			{"signing bit cleared", func(f []byte) bool {
				m := binary.LittleEndian.Uint16(f[smbHeader+2:])
				binary.LittleEndian.PutUint16(f[smbHeader+2:], m&^0x2)
				return m&0x2 != 0
			}},
			{"cipher GCM to CCM", func(f []byte) bool {
				i := encryptionContext(f)
				if i < 0 || binary.LittleEndian.Uint16(f[i:]) != 0x2 {
					return false
				}
				binary.LittleEndian.PutUint16(f[i:], 0x1)
				return true
			}},
		} {
			t.Run(tg.name+"/"+c.name, func(t *testing.T) {
				var tc *tamperConn
				dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
					var d net.Dialer
					raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", itoa(tg.port)))
					if err != nil {
						return nil, err
					}
					tc = &tamperConn{Conn: raw, edit: c.edit}
					return tc, nil
				}
				cfg := labConfig(t, tg.port, dial)
				b, err := Connect(t.Context(), cfg, tg.target())
				if tc == nil || !tc.hit {
					t.Skipf("tampering did not apply (%v)", err)
				}
				if err == nil {
					_ = b.Close()
					t.Fatalf("tampered negotiation was accepted: cipher %#x security %+v", uint16(b.Cipher()), b.security)
				}
				t.Logf("refused: %v (%+v)", err, DiagnosticOf(err))
			})
		}
	}
}
