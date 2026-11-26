package qrcode

import (
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"os"
	"strings"
	"testing"
)

type pythonVector struct {
	Data         string   `json:"data"`
	Level        string   `json:"level"`
	Overflow     bool     `json:"overflow"`
	Version      int      `json:"version"`
	Mask         int      `json:"mask"`
	MatrixSHA256 string   `json:"matrix_sha256"`
	Rows         []string `json:"rows"`
	SVGSHA256    string   `json:"svg_sha256"`
}

func loadVectors(t *testing.T) []pythonVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/python_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []pythonVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 200 {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	return file.Vectors
}

func levelOf(t *testing.T, name string) Level {
	t.Helper()
	l := strings.Index("LMQH", name)
	if l < 0 || len(name) != 1 {
		t.Fatalf("level %q", name)
	}
	return Level(l)
}

func rows(c *Code) []string {
	out := make([]string, c.Size())
	for r := range c.Size() {
		var b strings.Builder
		for col := range c.Size() {
			if c.Dark(r, col) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		out[r] = b.String()
	}
	return out
}

// TestPythonVectors compares every matrix with the one the Python release's
// qrcode library produces for the same input and level
// (testdata/python_vectors.py).
func TestPythonVectors(t *testing.T) {
	t.Parallel()
	versions := map[int]bool{}
	for i, v := range loadVectors(t) {
		data, err := hex.DecodeString(v.Data)
		if err != nil {
			t.Fatal(err)
		}
		code, err := Encode(data, levelOf(t, v.Level))
		if v.Overflow {
			if !errors.Is(err, ErrTooLong) {
				t.Errorf("vector %d (%d bytes, %s): err = %v, want ErrTooLong", i, len(data), v.Level, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		versions[code.Version] = true
		if code.Version != v.Version || code.Mask != v.Mask {
			t.Errorf("vector %d (%d bytes, %s): version %d mask %d, want %d mask %d", i, len(data), v.Level, code.Version, code.Mask, v.Version, v.Mask)
			continue
		}
		got := rows(code)
		sum := sha256.Sum256([]byte(strings.Join(got, "\n")))
		if hex.EncodeToString(sum[:]) != v.MatrixSHA256 {
			t.Errorf("vector %d (%d bytes, %s): matrix differs", i, len(data), v.Level)
			for r := range v.Rows {
				if got[r] != v.Rows[r] {
					t.Errorf("row %d\n got %s\nwant %s", r, got[r], v.Rows[r])
				}
			}
			continue
		}
		if v.SVGSHA256 != "" {
			sum := sha256.Sum256([]byte(SVG(code)))
			if hex.EncodeToString(sum[:]) != v.SVGSHA256 {
				t.Errorf("vector %d: SVG differs from the Python output", i)
			}
		}
	}
	for _, want := range []int{1, 7, 10, 27, 40} {
		if !versions[want] {
			t.Errorf("no vector covers version %d", want)
		}
	}
}

func TestSegments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []int
	}{
		{"", nil},
		{"0123", []int{modeNumeric}},
		{"HELLO WORLD", []int{modeAlnum}},
		{"hello", []int{modeByte}},
		{"x" + strings.Repeat("1", 20) + "y", []int{modeByte, modeNumeric, modeByte}},
		{"x" + strings.Repeat("1", 19) + "yyyy", []int{modeByte}},
		{"secret=" + strings.Repeat("A", 32) + "&x", []int{modeByte, modeAlnum, modeByte}},
	}
	for _, tt := range tests {
		var got []int
		for _, s := range segments([]byte(tt.in)) {
			got = append(got, s.mode)
		}
		if len(got) != len(tt.want) {
			t.Errorf("segments(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("segments(%q) = %v, want %v", tt.in, got, tt.want)
			}
		}
	}
}

func TestRejectsUnknownLevel(t *testing.T) {
	t.Parallel()
	if _, err := Encode([]byte("x"), Level(4)); err == nil {
		t.Fatal("Encode accepted level 4")
	}
	if _, err := Encode([]byte("x"), Level(-1)); err == nil {
		t.Fatal("Encode accepted level -1")
	}
}

func TestDarkOutside(t *testing.T) {
	t.Parallel()
	c, err := Encode([]byte("x"), M)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]int{{-1, 0}, {0, -1}, {c.Size(), 0}, {0, c.Size()}} {
		if c.Dark(p[0], p[1]) {
			t.Errorf("Dark(%d, %d) outside the symbol", p[0], p[1])
		}
	}
	if !c.Dark(0, 0) || !c.Dark(c.Size()-8, 8) {
		t.Error("finder corner or dark module is light")
	}
}

// TestRemainderVector checks the error correction of the worked example of
// ISO/IEC 18004 annex I ("01234567", version 1-M).
func TestRemainderVector(t *testing.T) {
	t.Parallel()
	data := []byte{0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11}
	want := []byte{0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55}
	got := remainder(data, 10)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("remainder = %x, want %x", got, want)
	}
}
