package terminal

import (
	"bytes"
	"regexp"
	"testing"
)

// pythonDA is the expression of app/ssh_manager.py.
var pythonDA = regexp.MustCompile(`\x1b\[[?>]?[0-9;]*c`)

func TestStripDAMatchesPython(t *testing.T) {
	for _, in := range []string{
		"", "plain", "\x1b[c", "\x1b[0c", "\x1b[?1;2c", "\x1b[>0;276;0c", "a\x1b[?64;1;2;6;9;15;18;21;22cb",
		"\x1b[?c", "\x1b[>?c", "\x1b[1;2H", "100c", "cat file", "\x1b\x1b[c", "\x1b[?1049h\x1b[c\x1b[32mx",
		"\x1b[", "\x1b[?", "\x1b", "x\x1b[12;", "ä\x1b[cö",
	} {
		got, _ := stripDA([]byte(in), false)
		if want := pythonDA.ReplaceAllString(in, ""); string(got) != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// A sequence split across reads is removed as if it came in one piece
// (K6 A8); the Python filter missed it.
func TestDAFilterAcrossReads(t *testing.T) {
	stream := "prompt$ \x1b[?1;2c and \x1b[>0;276;0c done"
	for cut := range len(stream) + 1 {
		var f daFilter
		out := append(f.write([]byte(stream[:cut])), f.write([]byte(stream[cut:]))...)
		out = append(out, f.flush()...)
		if string(out) != "prompt$  and  done" {
			t.Fatalf("split at %d: %q", cut, out)
		}
	}
}

// A held prefix that is not completed is sent unchanged, and a candidate
// longer than maxHeld is not held at all.
func TestDAFilterHoldBack(t *testing.T) {
	var f daFilter
	if out := f.write([]byte("vim\x1b[1")); string(out) != "vim" || !f.pending() {
		t.Fatalf("held: %q", out)
	}
	if out := f.flush(); string(out) != "\x1b[1" || f.pending() {
		t.Fatalf("flush: %q", out)
	}
	long := "\x1b[" + string(bytes.Repeat([]byte("1"), maxHeld))
	if out := f.write([]byte(long)); string(out) != long || f.pending() {
		t.Fatal("long candidate held back")
	}
}

func TestFilterInput(t *testing.T) {
	if got := filterInput([]byte("ls\x1b[?1;2c\r")); string(got) != "ls\r" {
		t.Fatalf("%q", got)
	}
	in := []byte("100c")
	if got := filterInput(in); &got[0] != &in[0] {
		t.Fatal("input without ESC is copied")
	}
	if got := filterInput([]byte("\x1b[")); string(got) != "\x1b[" {
		t.Fatalf("a partial sequence in input is kept: %q", got)
	}
}

// FuzzDAFilter: any split of any stream gives the result of the Python
// expression on the whole stream.
func FuzzDAFilter(f *testing.F) {
	f.Add([]byte("a\x1b[?1;2cb\x1b[0c"), uint8(3))
	f.Add([]byte("\x1b\x1b[>c\x1b[1;2H"), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, step uint8) {
		n := int(step)%16 + 1
		var fl daFilter
		var out []byte
		for i := 0; i < len(data); i += n {
			out = append(out, fl.write(data[i:min(i+n, len(data))])...)
		}
		out = append(out, fl.flush()...)
		whole, _ := stripDA(data, false)
		// The held prefix is bounded, so only a candidate of more than
		// maxHeld bytes split across reads may pass unfiltered.
		if len(data) <= maxHeld && !bytes.Equal(out, whole) {
			t.Fatalf("split %d: %q, whole %q", n, out, whole)
		}
		if want := pythonDA.ReplaceAll(data, nil); !bytes.Equal(whole, want) {
			t.Fatalf("whole %q, python %q", whole, want)
		}
	})
}

func TestRing(t *testing.T) {
	r := ring{max: 10}
	for i := range 5 {
		r.add(chunk{seq: uint64(i + 1), data: []byte("abc")})
	}
	if r.size != 9 || r.chunks[0].seq != 3 {
		t.Fatalf("size %d, first %d", r.size, r.chunks[0].seq)
	}
	if out, full := r.since(4); full || len(out) != 1 || out[0].seq != 5 {
		t.Fatalf("delta: %v %v", out, full)
	}
	if out, full := r.since(1); !full || len(out) != 3 {
		t.Fatalf("gap: %v %v", out, full)
	}
	if out, full := r.since(5); full || len(out) != 0 {
		t.Fatalf("up to date: %v %v", out, full)
	}
	r.add(chunk{seq: 6, data: []byte("0123456789ABC")})
	if r.size != 10 || len(r.chunks) != 1 || string(r.chunks[0].data) != "3456789ABC" {
		t.Fatalf("oversized chunk: %q", r.chunks[0].data)
	}
	if out, full := (&ring{max: 1}).since(0); out != nil || !full {
		t.Fatal("empty ring")
	}
}

func TestCoalesce(t *testing.T) {
	in := []chunk{{1, []byte("ab")}, {2, []byte("cd")}, {3, []byte("efgh")}, {4, []byte("i")}}
	out := coalesce(in, 4)
	if len(out) != 3 || string(out[0].data) != "abcd" || out[0].seq != 2 || out[1].seq != 3 || out[2].seq != 4 {
		t.Fatalf("%+v", out)
	}
	if string(in[0].data) != "ab" {
		t.Fatal("coalesce changed the ring's chunks")
	}
}
