package legacy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// A minimal CBOR (RFC 8949) decoder for COSE keys (RFC 9052). It accepts
// definite-length integers, byte strings, text strings, arrays, maps and
// the simple values false, true and null; everything else, including
// indefinite lengths, tags and floats, is rejected. Map keys must be
// integers or text strings and must not repeat.

const (
	cborMaxDepth = 8
	cborMaxItems = 64
	// cborMaxString bounds byte and text strings; an RSA-4096 modulus is 512.
	cborMaxString = 1 << 16
)

var errCBOR = errors.New("legacy: invalid CBOR")

// cborMap is a decoded map with integer or text keys.
type cborMap map[any]any

type cborDecoder struct {
	data []byte
	pos  int
}

// decodeCBOR decodes exactly one data item; trailing bytes are an error.
func decodeCBOR(data []byte) (any, error) {
	d := cborDecoder{data: data}
	v, err := d.item(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		return nil, fmt.Errorf("%w: trailing bytes", errCBOR)
	}
	return v, nil
}

func (d *cborDecoder) head() (major byte, arg uint64, err error) {
	if d.pos >= len(d.data) {
		return 0, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	b := d.data[d.pos]
	d.pos++
	major, info := b>>5, b&0x1f
	var size int
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		size = 1
	case info == 25:
		size = 2
	case info == 26:
		size = 4
	case info == 27:
		size = 8
	default:
		return 0, 0, fmt.Errorf("%w: unsupported additional information %d", errCBOR, info)
	}
	if len(d.data)-d.pos < size {
		return 0, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	var buf [8]byte
	copy(buf[8-size:], d.data[d.pos:d.pos+size])
	d.pos += size
	return major, binary.BigEndian.Uint64(buf[:]), nil
}

func (d *cborDecoder) item(depth int) (any, error) {
	if depth > cborMaxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", errCBOR)
	}
	major, arg, err := d.head()
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
		if arg > cborMaxString {
			return nil, fmt.Errorf("%w: string too long", errCBOR)
		}
		n := int(arg) // #nosec G115 -- bounded by cborMaxString above
		if n > len(d.data)-d.pos {
			return nil, fmt.Errorf("%w: truncated string", errCBOR)
		}
		b := d.data[d.pos : d.pos+n]
		d.pos += n
		if major == 3 {
			return string(b), nil
		}
		return append([]byte(nil), b...), nil
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
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
	}
	return nil, fmt.Errorf("%w: unsupported major type %d", errCBOR, major)
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
