package terminal

// chunk is output of a session with the sequence of its last read.
type chunk struct {
	seq  uint64
	data []byte
}

// ring keeps the most recent output of a session, bounded in bytes, so a
// reconnecting browser can redraw the screen. Not safe for concurrent use;
// the session lock guards it.
type ring struct {
	max    int
	size   int
	chunks []chunk
}

func (r *ring) add(c chunk) {
	r.chunks = append(r.chunks, c)
	r.size += len(c.data)
	drop := 0
	for r.size > r.max && drop < len(r.chunks)-1 {
		r.size -= len(r.chunks[drop].data)
		drop++
	}
	if drop > 0 {
		// Copy down instead of reslicing so the backing array does not keep
		// dropped chunks reachable.
		n := copy(r.chunks, r.chunks[drop:])
		clear(r.chunks[n:])
		r.chunks = r.chunks[:n]
	}
	// One chunk alone may exceed the bound (a read is at most ReadSize);
	// keep its tail.
	if r.size > r.max && len(r.chunks) == 1 {
		c := &r.chunks[0]
		c.data = append([]byte(nil), c.data[len(c.data)-r.max:]...)
		r.size = len(c.data)
	}
}

// since returns the chunks after seq and whether they form a gapless delta.
// When output after seq was already dropped (or seq is 0), it returns
// everything kept and full=true: the client must reset its screen first.
func (r *ring) since(seq uint64) (out []chunk, full bool) {
	if len(r.chunks) == 0 {
		return nil, seq == 0
	}
	first := r.chunks[0].seq
	if seq == 0 || seq+1 < first {
		return append([]chunk(nil), r.chunks...), true
	}
	for i, c := range r.chunks {
		if c.seq > seq {
			return append([]chunk(nil), r.chunks[i:]...), false
		}
	}
	return nil, false
}

// coalesce merges consecutive chunks into frames of at most maxFrame bytes,
// so a replay of many small reads (typing) needs few frames of the output
// budget. A merged frame carries the sequence of its last chunk.
func coalesce(chunks []chunk, maxFrame int) []chunk {
	var out []chunk
	for _, c := range chunks {
		if n := len(out); n > 0 && len(out[n-1].data)+len(c.data) <= maxFrame {
			out[n-1].data = append(out[n-1].data, c.data...)
			out[n-1].seq = c.seq
			continue
		}
		out = append(out, chunk{seq: c.seq, data: append(make([]byte, 0, max(len(c.data), min(maxFrame, 4096))), c.data...)})
	}
	return out
}
