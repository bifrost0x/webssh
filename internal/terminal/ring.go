package terminal

// chunk is output of a session: the reads first through seq.
type chunk struct {
	first uint64
	seq   uint64
	data  []byte
}

// Small reads are merged into the newest chunk up to mergeLimit bytes, so
// output in tiny packets does not turn the replay buffer into hundreds of
// thousands of chunks. maxRingChunks is the resulting bound for a buffer
// of DefaultReplayBytes; the ring enforces it for any size.
const (
	mergeLimit    = 4096
	maxRingChunks = 1024
)

// ring keeps the most recent output of a session, bounded in bytes and
// chunks, so a reconnecting browser can redraw the screen. Not safe for
// concurrent use; the session lock guards it.
type ring struct {
	max    int
	size   int
	head   int // chunks[:head] are dropped and wait for compaction
	chunks []chunk
}

func (r *ring) add(c chunk) {
	if c.first == 0 {
		c.first = c.seq
	}
	if n := len(r.chunks); n > r.head && len(r.chunks[n-1].data)+len(c.data) <= mergeLimit {
		last := &r.chunks[n-1]
		last.data = append(last.data, c.data...)
		last.seq = c.seq
	} else {
		c.data = append(make([]byte, 0, max(len(c.data), min(mergeLimit, 2*len(c.data)))), c.data...)
		r.chunks = append(r.chunks, c)
	}
	r.size += len(c.data)
	for r.head < len(r.chunks)-1 && (r.size > r.max || len(r.chunks)-r.head > maxRingChunks) {
		r.size -= len(r.chunks[r.head].data)
		r.chunks[r.head] = chunk{}
		r.head++
	}
	// Compact once the dropped prefix is as long as the live part, so a
	// drop costs O(1) amortized.
	if r.head > 0 && r.head >= len(r.chunks)-r.head {
		n := copy(r.chunks, r.chunks[r.head:])
		clear(r.chunks[n:])
		r.chunks = r.chunks[:n]
		r.head = 0
	}
	// One chunk alone may exceed the bound (a read is at most ReadSize);
	// keep its tail.
	if live := r.chunks[r.head:]; r.size > r.max && len(live) == 1 {
		c := &live[0]
		c.data = append([]byte(nil), c.data[len(c.data)-r.max:]...)
		r.size = len(c.data)
	}
}

// since returns the chunks after seq and whether they form a gapless delta.
// When output after seq was already dropped, seq lies inside a merged
// chunk or seq is 0, it returns everything kept and full=true: the client
// must reset its screen first.
func (r *ring) since(seq uint64) (out []chunk, full bool) {
	live := r.chunks[r.head:]
	if len(live) == 0 {
		return nil, seq == 0
	}
	if seq == 0 || seq+1 < live[0].first {
		return append([]chunk(nil), live...), true
	}
	for i, c := range live {
		if c.seq > seq {
			if c.first <= seq {
				return append([]chunk(nil), live...), true
			}
			return append([]chunk(nil), live[i:]...), false
		}
	}
	return nil, false
}

// coalesce merges consecutive chunks into frames of at most maxFrame bytes,
// so a replay needs few frames of the output budget. A merged frame
// carries the sequence of its last chunk. The ring's chunks are not
// changed.
func coalesce(chunks []chunk, maxFrame int) []chunk {
	var out []chunk
	for _, c := range chunks {
		if n := len(out); n > 0 && len(out[n-1].data)+len(c.data) <= maxFrame {
			out[n-1].data = append(out[n-1].data, c.data...)
			out[n-1].seq = c.seq
			continue
		}
		out = append(out, chunk{first: c.first, seq: c.seq, data: append(make([]byte, 0, max(len(c.data), min(maxFrame, 4096))), c.data...)})
	}
	return out
}
