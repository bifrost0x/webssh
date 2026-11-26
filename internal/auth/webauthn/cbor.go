package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// A strict CBOR (RFC 8949) decoder for the three structures WebAuthn
// carries: the attestation object, COSE keys and the extension map of the
// authenticator data. It accepts definite-length integers, byte strings,
// UTF-8 text strings, arrays, maps and the simple values false, true and
// null. Indefinite lengths, tags, floats, undefined and other simple values
// are rejected, as are duplicate map keys, map keys other than integers and
// text strings, and nesting, counts or lengths beyond the limits below.
// Integer heads that are longer than necessary are accepted: the Python
// release stored COSE keys as the authenticator sent them, and signatures
// cover the raw bytes, not a re-encoding.

const (
	cborMaxDepth  = 8
	cborMaxItems  = 64
	cborMaxString = 1 << 16 // an attestation certificate fits; the request body is smaller
)

var errCBOR = errors.New("webauthn: invalid CBOR")

// cborMap is a decoded map; keys are int64 or string.
type cborMap map[any]any

type cborDecoder struct {
	data []byte
	pos  int
}

// decodeCBOR decodes exactly one data item; trailing bytes are an error.
func decodeCBOR(data []byte) (any, error) {
	v, n, err := decodeCBORPrefix(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, fmt.Errorf("%w: trailing bytes", errCBOR)
	}
	return v, nil
}

// decodeCBORPrefix decodes the first data item of data and returns its
// length in bytes.
func decodeCBORPrefix(data []byte) (any, int, error) {
	d := cborDecoder{data: data}
	v, err := d.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

func (d *cborDecoder) head() (major byte, info byte, arg uint64, err error) {
	if d.pos >= len(d.data) {
		return 0, 0, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	b := d.data[d.pos]
	d.pos++
	major, info = b>>5, b&0x1f
	var size int
	switch {
	case info < 24:
		return major, info, uint64(info), nil
	case info == 24:
		size = 1
	case info == 25:
		size = 2
	case info == 26:
		size = 4
	case info == 27:
		size = 8
	default: // 28-30 reserved, 31 indefinite length or break
		return 0, 0, 0, fmt.Errorf("%w: unsupported additional information %d", errCBOR, info)
	}
	if len(d.data)-d.pos < size {
		return 0, 0, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	var buf [8]byte
	copy(buf[8-size:], d.data[d.pos:d.pos+size])
	d.pos += size
	return major, info, binary.BigEndian.Uint64(buf[:]), nil
}

func (d *cborDecoder) item(depth int) (any, error) {
	if depth > cborMaxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", errCBOR)
	}
	major, info, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", errCBOR)
		}
		return int64(arg), nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", errCBOR)
		}
		return -1 - int64(arg), nil
	case 2, 3:
		b, err := d.bytes(arg)
		if err != nil {
			return nil, err
		}
		if major == 3 {
			if !utf8.Valid(b) {
				return nil, fmt.Errorf("%w: text string is not UTF-8", errCBOR)
			}
			return string(b), nil
		}
		return b, nil
	case 4:
		if arg > cborMaxItems {
			return nil, fmt.Errorf("%w: array too long", errCBOR)
		}
		out := make([]any, 0, arg)
		for range arg {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		return d.mapItems(arg, depth)
	case 7:
		// Only the one-byte simple values; a float or a two-byte simple
		// value has info 24 or more.
		switch {
		case info == 20:
			return false, nil
		case info == 21:
			return true, nil
		case info == 22:
			return nil, nil
		}
		return nil, fmt.Errorf("%w: unsupported simple value or float", errCBOR)
	}
	return nil, fmt.Errorf("%w: unsupported major type %d", errCBOR, major) // tags (6)
}

func (d *cborDecoder) bytes(n uint64) ([]byte, error) {
	if n > cborMaxString {
		return nil, fmt.Errorf("%w: string too long", errCBOR)
	}
	size := int(n) // #nosec G115 -- bounded by cborMaxString above
	if size > len(d.data)-d.pos {
		return nil, fmt.Errorf("%w: truncated string", errCBOR)
	}
	b := d.data[d.pos : d.pos+size : d.pos+size]
	d.pos += size
	return b, nil
}

func (d *cborDecoder) mapItems(n uint64, depth int) (cborMap, error) {
	if n > cborMaxItems {
		return nil, fmt.Errorf("%w: map too long", errCBOR)
	}
	out := make(cborMap, n)
	for range n {
		k, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		switch k.(type) {
		case int64, string:
		default:
			return nil, fmt.Errorf("%w: unsupported map key", errCBOR)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("%w: duplicate map key", errCBOR)
		}
		v, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}
