package audit

import (
	"errors"
	"math"
	"math/big"
	"strconv"
	"unicode/utf8"
)

// The audit view and export read every line back into a value and write
// it again, as the Python release does with json.loads and json.dumps.
// value is that round trip: it accepts what json.loads accepts (NaN,
// Infinity, repeated member names where the last value wins at the place
// of the first, escaped lone surrogates, integers of any size) and keeps
// member order, so the export repeats Python's bytes.

type valueKind uint8

const (
	kindNull valueKind = iota
	kindBool
	kindInt
	kindFloat
	kindString
	kindArray
	kindObject
)

type value struct {
	kind  valueKind
	b     bool
	num   string  // kindInt: canonical decimal digits
	f     float64 // kindFloat
	str   []rune  // kindString; may hold lone surrogates
	items []value // kindArray
	keys  [][]rune
	vals  []value // kindObject, in insertion order
}

// maxDepth bounds nesting; Python stops at its recursion limit and the
// release then failed the whole request.
const maxDepth = 256

// maxIntDigits is Python's default int_max_str_digits; a longer integer
// made json.loads raise.
const maxIntDigits = 4300

var errDecode = errors.New("audit: not JSON")

type decoder struct {
	s     []byte
	i     int
	depth int
}

// decodeLine parses one line like json.loads.
func decodeLine(line []byte) (value, error) {
	d := decoder{s: line}
	d.space()
	v, err := d.value()
	if err != nil {
		return value{}, err
	}
	d.space()
	if d.i != len(d.s) {
		return value{}, errDecode
	}
	return v, nil
}

func (d *decoder) space() {
	for d.i < len(d.s) {
		switch d.s[d.i] {
		case ' ', '\t', '\n', '\r':
			d.i++
		default:
			return
		}
	}
}

func (d *decoder) literal(word string) bool {
	if len(d.s)-d.i >= len(word) && string(d.s[d.i:d.i+len(word)]) == word {
		d.i += len(word)
		return true
	}
	return false
}

func (d *decoder) value() (value, error) {
	if d.i >= len(d.s) {
		return value{}, errDecode
	}
	switch c := d.s[d.i]; {
	case c == '{':
		return d.object()
	case c == '[':
		return d.array()
	case c == '"':
		s, err := d.string()
		return value{kind: kindString, str: s}, err
	case d.literal("null"):
		return value{kind: kindNull}, nil
	case d.literal("true"):
		return value{kind: kindBool, b: true}, nil
	case d.literal("false"):
		return value{kind: kindBool}, nil
	case d.literal("NaN"):
		return value{kind: kindFloat, f: math.NaN()}, nil
	case d.literal("Infinity"):
		return value{kind: kindFloat, f: math.Inf(1)}, nil
	case d.literal("-Infinity"):
		return value{kind: kindFloat, f: math.Inf(-1)}, nil
	case c == '-' || c >= '0' && c <= '9':
		return d.number()
	}
	return value{}, errDecode
}

func (d *decoder) enter() error {
	if d.depth++; d.depth > maxDepth {
		return errDecode
	}
	d.i++
	d.space()
	return nil
}

func (d *decoder) object() (value, error) {
	if err := d.enter(); err != nil {
		return value{}, err
	}
	v := value{kind: kindObject}
	index := map[string]int{}
	if d.i < len(d.s) && d.s[d.i] == '}' {
		d.i++
		d.depth--
		return v, nil
	}
	for {
		if d.i >= len(d.s) || d.s[d.i] != '"' {
			return value{}, errDecode
		}
		k, err := d.string()
		if err != nil {
			return value{}, err
		}
		d.space()
		if d.i >= len(d.s) || d.s[d.i] != ':' {
			return value{}, errDecode
		}
		d.i++
		d.space()
		item, err := d.value()
		if err != nil {
			return value{}, err
		}
		if at, ok := index[wtf8(k)]; ok {
			v.vals[at] = item
		} else {
			index[wtf8(k)] = len(v.keys)
			v.keys, v.vals = append(v.keys, k), append(v.vals, item)
		}
		d.space()
		if d.i < len(d.s) && d.s[d.i] == ',' {
			d.i++
			d.space()
			continue
		}
		if d.i < len(d.s) && d.s[d.i] == '}' {
			d.i++
			d.depth--
			return v, nil
		}
		return value{}, errDecode
	}
}

func (d *decoder) array() (value, error) {
	if err := d.enter(); err != nil {
		return value{}, err
	}
	v := value{kind: kindArray}
	if d.i < len(d.s) && d.s[d.i] == ']' {
		d.i++
		d.depth--
		return v, nil
	}
	for {
		item, err := d.value()
		if err != nil {
			return value{}, err
		}
		v.items = append(v.items, item)
		d.space()
		if d.i < len(d.s) && d.s[d.i] == ',' {
			d.i++
			d.space()
			continue
		}
		if d.i < len(d.s) && d.s[d.i] == ']' {
			d.i++
			d.depth--
			return v, nil
		}
		return value{}, errDecode
	}
}

func digits(s []byte, i int) int {
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

// number follows the grammar of the json module's NUMBER_RE.
func (d *decoder) number() (value, error) {
	start, i := d.i, d.i
	if d.s[i] == '-' {
		i++
	}
	switch {
	case i < len(d.s) && d.s[i] == '0':
		i++
	case i < len(d.s) && d.s[i] >= '1' && d.s[i] <= '9':
		i = digits(d.s, i)
	default:
		return value{}, errDecode
	}
	isInt := true
	if i+1 < len(d.s) && d.s[i] == '.' && d.s[i+1] >= '0' && d.s[i+1] <= '9' {
		i, isInt = digits(d.s, i+1), false
	}
	if i < len(d.s) && (d.s[i] == 'e' || d.s[i] == 'E') {
		j := i + 1
		if j < len(d.s) && (d.s[j] == '+' || d.s[j] == '-') {
			j++
		}
		if k := digits(d.s, j); k > j {
			i, isInt = k, false
		}
	}
	text := string(d.s[start:i])
	d.i = i
	if isInt {
		if len(text) > maxIntDigits {
			return value{}, errDecode
		}
		n, _ := new(big.Int).SetString(text, 10)
		return value{kind: kindInt, num: n.String()}, nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return value{}, errDecode
	}
	return value{kind: kindFloat, f: f}, nil
}

func hex4(s []byte) (rune, bool) {
	if len(s) < 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(string(s[:4]), 16, 32)
	return rune(n), err == nil // #nosec G115 -- four hex digits fit a rune
}

// string reads a string like json.loads with strict=True: control
// characters must be escaped, a surrogate pair escape joins, a lone
// surrogate escape stays as it is.
func (d *decoder) string() ([]rune, error) {
	d.i++
	var out []rune
	for d.i < len(d.s) {
		c := d.s[d.i]
		switch {
		case c == '"':
			d.i++
			return out, nil
		case c < 0x20:
			return nil, errDecode
		case c == '\\':
			if d.i+1 >= len(d.s) {
				return nil, errDecode
			}
			e := d.s[d.i+1]
			d.i += 2
			switch e {
			case '"', '\\', '/':
				out = append(out, rune(e))
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, ok := hex4(d.s[d.i:])
				if !ok {
					return nil, errDecode
				}
				d.i += 4
				if r >= 0xd800 && r <= 0xdbff && d.i+1 < len(d.s) && d.s[d.i] == '\\' && d.s[d.i+1] == 'u' {
					if lo, ok := hex4(d.s[d.i+2:]); ok && lo >= 0xdc00 && lo <= 0xdfff {
						r = 0x10000 + (r-0xd800)<<10 + (lo - 0xdc00)
						d.i += 6
					}
				}
				out = append(out, r)
			default:
				return nil, errDecode
			}
		default:
			r, n := utf8.DecodeRune(d.s[d.i:])
			out = append(out, r)
			d.i += n
		}
	}
	return nil, errDecode
}

// wtf8 is a map key that tells lone surrogates apart.
func wtf8(rs []rune) string {
	b := make([]byte, 0, len(rs))
	for _, r := range rs {
		if r >= 0xd800 && r <= 0xdfff {
			b = append(b, byte(0xe0|r>>12), byte(0x80|(r>>6)&0x3f), byte(0x80|r&0x3f)) // #nosec G115 -- a surrogate has 16 bits
			continue
		}
		b = utf8.AppendRune(b, r)
	}
	return string(b)
}

// member returns the value of key in an object.
func (v value) member(key string) (value, bool) {
	for i, k := range v.keys {
		if string(k) == key {
			return v.vals[i], true
		}
	}
	return value{}, false
}
