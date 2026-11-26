package terminal

import "bytes"

// Device attributes (DA) are the sequences ESC [ c, ESC [ ? … c and
// ESC [ > … c: a query from the host or the terminal's reply. The Python
// release removes them from output and input with the expression
// \x1b\[[?>]?[0-9;]*c, so xterm.js never answers a query and a reply typed
// back by the browser never reaches the shell. The output filter works on
// bytes across reads (K6 A8); ESC never occurs inside a UTF-8 sequence, so
// the raw stream can be filtered without decoding it.

// maxHeld bounds the possible DA prefix kept at the end of a read. It is
// the size of one read, so a sequence split across reads is filtered like
// the expression on the whole stream whatever its length; only a
// candidate longer than a read is sent unchanged. DA3 (ESC [ = c) is not
// matched, as in the Python release.
const maxHeld = DefaultReadSize

type daMatch int

const (
	daNone    daMatch = iota // not a DA sequence
	daPartial                // a prefix of one; more bytes decide
	daFull                   // a complete sequence of the returned length
)

// matchDA inspects b, which starts with ESC.
func matchDA(b []byte) (int, daMatch) {
	if len(b) < 2 {
		return 0, daPartial
	}
	if b[1] != '[' {
		return 0, daNone
	}
	k := 2
	if k < len(b) && (b[k] == '?' || b[k] == '>') {
		k++
	}
	for k < len(b) && (b[k] >= '0' && b[k] <= '9' || b[k] == ';') {
		k++
	}
	switch {
	case k == len(b):
		return 0, daPartial
	case b[k] == 'c':
		return k + 1, daFull
	}
	return 0, daNone
}

// stripDA removes complete DA sequences from b. With hold set, a possible
// prefix at the end is returned separately instead of being copied.
func stripDA(b []byte, hold bool) (out, held []byte) {
	out = make([]byte, 0, len(b))
	for len(b) > 0 {
		j := bytes.IndexByte(b, 0x1b)
		if j < 0 {
			return append(out, b...), nil
		}
		out = append(out, b[:j]...)
		b = b[j:]
		n, m := matchDA(b)
		switch {
		case m == daFull:
			b = b[n:]
		case m == daPartial && hold && len(b) <= maxHeld:
			return out, append([]byte(nil), b...)
		default:
			out = append(out, b[0])
			b = b[1:]
		}
	}
	return out, nil
}

// daFilter filters a byte stream read in pieces.
type daFilter struct{ held []byte }

// write returns the filtered output of p; a possible DA prefix at its end
// is kept until the next write or flush.
func (f *daFilter) write(p []byte) []byte {
	if len(f.held) > 0 {
		p = append(f.held, p...)
		f.held = nil
	}
	out, held := stripDA(p, true)
	f.held = held
	return out
}

// pending reports whether bytes are held back.
func (f *daFilter) pending() bool { return len(f.held) > 0 }

// flush returns the held bytes unchanged: no further byte arrived in time,
// so they are not a DA sequence the host sent in one piece.
func (f *daFilter) flush() []byte {
	out := f.held
	f.held = nil
	return out
}

// filterInput removes DA replies from one input frame, as the Python
// release did for every input event.
func filterInput(p []byte) []byte {
	if bytes.IndexByte(p, 0x1b) < 0 {
		return p
	}
	out, _ := stripDA(p, false)
	return out
}
