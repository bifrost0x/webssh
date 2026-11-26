package qrcode

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// png renders c with scale pixels per module and the quiet zone.
func renderPNG(t testing.TB, c *Code, scale int) []byte {
	t.Helper()
	side := (c.Size() + 2*quietZone) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for y := range side {
		for x := range side {
			v := color.Gray{Y: 255}
			if c.Dark(y/scale-quietZone, x/scale-quietZone) {
				v = color.Gray{Y: 0}
			}
			img.SetGray(x, y, v)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestIndependentDecoder reads the codes back with ZBar, a decoder that
// shares no code with this package or with the Python library. CI images
// without zbarimg skip it; it runs on every developer machine that has it.
func TestIndependentDecoder(t *testing.T) {
	t.Parallel()
	zbar, err := exec.LookPath("zbarimg")
	if err != nil {
		t.Skip("zbarimg is not installed")
	}
	inputs := []string{
		"otpauth://totp/WebSSH:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=WebSSH",
		"otpauth://totp/WebSSH:%C3%BCser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=WebSSH",
		"01234567890123456789012345678901234567890",
		"HELLO WORLD 1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		strings.Repeat("WebSSH terminal ", 60),
	}
	dir := t.TempDir()
	for i, in := range inputs {
		for _, level := range []Level{L, M, Q, H} {
			c, err := Encode([]byte(in), level)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "code.png")
			if err := os.WriteFile(path, renderPNG(t, c, 4), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.CommandContext(t.Context(), zbar, "--quiet", "--raw", "-Sdisable", "-Sqrcode.enable", path).Output() // #nosec G204 -- fixed binary from PATH, test-generated file
			if err != nil {
				t.Fatalf("input %d level %d (version %d): zbarimg: %v", i, level, c.Version, err)
			}
			if got := strings.TrimSuffix(string(out), "\n"); got != in {
				t.Errorf("input %d level %d: decoded %q", i, level, got)
			}
		}
	}
}

// readFormat reads the format information next to the top left finder and
// returns level and mask, or ok=false if it is not a valid BCH word.
func readFormat(c *Code) (Level, int, bool) {
	word := 0
	for i := range 15 {
		var dark bool
		switch {
		case i < 6:
			dark = c.Dark(i, 8)
		case i < 8:
			dark = c.Dark(i+1, 8)
		default:
			dark = c.Dark(c.Size()-15+i, 8)
		}
		if dark {
			word |= 1 << i
		}
	}
	for level := L; level <= H; level++ {
		for mask := range 8 {
			if bchFormat(level.formatBits()<<3|mask) == word {
				return level, mask, true
			}
		}
	}
	return 0, 0, false
}

func FuzzEncode(f *testing.F) {
	f.Add([]byte("otpauth://totp/WebSSH:a?secret=ABC&issuer=WebSSH"), uint8(1))
	f.Add([]byte("12345678901234567890123"), uint8(0))
	f.Add([]byte{}, uint8(3))
	f.Fuzz(func(t *testing.T, data []byte, lv uint8) {
		level := Level(lv % 4)
		c, err := Encode(data, level)
		if err != nil {
			if err != ErrTooLong {
				t.Fatalf("Encode: %v", err)
			}
			return
		}
		if c.Size() != 17+4*c.Version || c.Version < 1 || c.Version > 40 {
			t.Fatalf("version %d with size %d", c.Version, c.Size())
		}
		gotLevel, gotMask, ok := readFormat(c)
		if !ok || gotLevel != level || gotMask != c.Mask {
			t.Fatalf("format information %v %d %v, want %v %d", gotLevel, gotMask, ok, level, c.Mask)
		}
		again, err := Encode(data, level)
		if err != nil || strings.Join(rows(again), "") != strings.Join(rows(c), "") {
			t.Fatal("Encode is not deterministic")
		}
		dark := 0
		for r := range c.Size() {
			for col := range c.Size() {
				if c.Dark(r, col) {
					dark++
				}
			}
		}
		if n := strings.Count(SVG(c), "V"); n != dark {
			t.Fatalf("SVG has %d squares, matrix %d dark modules", n, dark)
		}
	})
}
