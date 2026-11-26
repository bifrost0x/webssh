// Package ldapproto implements the subset of LDAPv3 (RFC 4511) that sign-in
// needs: StartTLS, simple bind, subtree search and unbind, and a search
// filter compiler that accepts exactly what libldap (OpenLDAP 2.6), the
// client library of the Python release, accepts. It speaks only over TLS;
// a plaintext connection is never handed to callers.
//
// This is own BER and protocol code (tier C, plan K7): every decoder bounds
// sizes, accepts only definite lengths and is fuzzed.
package ldapproto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// BER class bits (X.690 section 8.1.2).
const (
	classUniversal   = 0x00
	classApplication = 0x40
	classContext     = 0x80
	constructedBit   = 0x20
)

// Universal tags used by LDAP.
const (
	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagEnumerated  = 0x0a
	tagSequence    = 0x10 | constructedBit
	tagSet         = 0x11 | constructedBit
)

// maxElement bounds every decoded length; it is far above the largest
// message the client accepts (maxSearchSize).
const maxElement = 1 << 24

// ErrMalformed reports a protocol element that does not follow the
// restricted BER encoding LDAP requires (RFC 4511 section 5.1).
var ErrMalformed = errors.New("ldap: malformed protocol element")

// element is one decoded BER TLV. Tag holds the full identifier octet;
// LDAP never uses high tag numbers, so one octet is always enough.
type element struct {
	tag     byte
	content []byte
}

func (e element) constructed() bool { return e.tag&constructedBit != 0 }

// appendLength appends a definite length in the shortest form.
func appendLength(dst []byte, n int) []byte {
	if n < 0x80 {
		return append(dst, byte(n)) // #nosec G115 -- n is a len() below 0x80
	}
	var buf [8]byte
	i := len(buf)
	for v := n; v > 0; v >>= 8 {
		i--
		buf[i] = byte(v)
	}
	dst = append(dst, 0x80|byte(len(buf)-i))
	return append(dst, buf[i:]...)
}

func appendTLV(dst []byte, tag byte, content []byte) []byte {
	dst = append(dst, tag)
	dst = appendLength(dst, len(content))
	return append(dst, content...)
}

func appendOctetString(dst []byte, tag byte, s string) []byte {
	dst = append(dst, tag)
	dst = appendLength(dst, len(s))
	return append(dst, s...)
}

// appendInt encodes a two's complement integer in minimal form.
func appendInt(dst []byte, tag byte, v int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v)) // #nosec G115 -- two's complement bit pattern intended
	b := buf[:]
	for len(b) > 1 && ((b[0] == 0x00 && b[1]&0x80 == 0) || (b[0] == 0xff && b[1]&0x80 != 0)) {
		b = b[1:]
	}
	return appendTLV(dst, tag, b)
}

func appendBool(dst []byte, tag byte, v bool) []byte {
	b := byte(0x00)
	if v {
		b = 0xff
	}
	return appendTLV(dst, tag, []byte{b})
}

// parseElement splits the first TLV off data. It accepts only definite
// lengths of at most four octets, as LDAP forbids the indefinite form.
func parseElement(data []byte) (element, []byte, error) {
	if len(data) < 2 {
		return element{}, nil, ErrMalformed
	}
	tag := data[0]
	if tag&0x1f == 0x1f {
		return element{}, nil, fmt.Errorf("%w: high tag number", ErrMalformed)
	}
	length, header, err := decodeLength(data[1:])
	if err != nil {
		return element{}, nil, err
	}
	rest := data[1+header:]
	if length > len(rest) {
		return element{}, nil, fmt.Errorf("%w: truncated element", ErrMalformed)
	}
	return element{tag: tag, content: rest[:length]}, rest[length:], nil
}

func decodeLength(data []byte) (length, consumed int, err error) {
	if len(data) == 0 {
		return 0, 0, ErrMalformed
	}
	first := data[0]
	if first < 0x80 {
		return int(first), 1, nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return 0, 0, fmt.Errorf("%w: indefinite length", ErrMalformed)
	}
	if count > 4 || len(data) < 1+count {
		return 0, 0, fmt.Errorf("%w: length field", ErrMalformed)
	}
	n, err := lengthValue(data[1 : 1+count])
	if err != nil {
		return 0, 0, err
	}
	return n, 1 + count, nil
}

// lengthValue decodes the octets of a long-form length. It works in 64
// bits, so that four octets cannot wrap to a negative int on 32-bit
// platforms, and refuses lengths above maxElement.
func lengthValue(octets []byte) (int, error) {
	var v uint64
	for _, b := range octets {
		v = v<<8 | uint64(b)
	}
	if v > maxElement {
		return 0, fmt.Errorf("%w: length field", ErrMalformed)
	}
	return int(v), nil // #nosec G115 -- bounded by maxElement above
}

// children parses the content of a constructed element into its members.
func (e element) children() ([]element, error) {
	if !e.constructed() {
		return nil, fmt.Errorf("%w: expected constructed element", ErrMalformed)
	}
	var out []element
	rest := e.content
	for len(rest) > 0 {
		child, next, err := parseElement(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, child)
		rest = next
	}
	return out, nil
}

func (e element) integer() (int64, error) {
	c := e.content
	if len(c) == 0 || len(c) > 8 {
		return 0, fmt.Errorf("%w: integer size", ErrMalformed)
	}
	if len(c) > 1 && ((c[0] == 0x00 && c[1]&0x80 == 0) || (c[0] == 0xff && c[1]&0x80 != 0)) {
		return 0, fmt.Errorf("%w: non-minimal integer", ErrMalformed)
	}
	v := int64(int8(c[0])) // #nosec G115 -- sign extension of the leading octet intended
	for _, b := range c[1:] {
		v = v<<8 | int64(b)
	}
	return v, nil
}

// readMessage reads one complete top-level element from r. maxSize bounds
// the memory a server can make the client allocate.
func readMessage(r *bufio.Reader, maxSize int) ([]byte, error) {
	header := make([]byte, 2, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != tagSequence {
		return nil, fmt.Errorf("%w: message is not a sequence", ErrMalformed)
	}
	var length int
	if header[1] < 0x80 {
		length = int(header[1])
	} else {
		count := int(header[1] & 0x7f)
		if count == 0 || count > 4 {
			return nil, fmt.Errorf("%w: length field", ErrMalformed)
		}
		extra := make([]byte, count)
		if _, err := io.ReadFull(r, extra); err != nil {
			return nil, err
		}
		header = append(header, extra...)
		var err error
		if length, err = lengthValue(extra); err != nil {
			return nil, err
		}
	}
	if length > maxSize {
		return nil, fmt.Errorf("%w: message of %d bytes exceeds limit", ErrMalformed, length)
	}
	msg := make([]byte, len(header)+length)
	copy(msg, header)
	if _, err := io.ReadFull(r, msg[len(header):]); err != nil {
		return nil, err
	}
	return msg, nil
}
