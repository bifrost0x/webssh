package qrcode

import (
	"strconv"
	"strings"
)

// quietZone is the light border in modules around the symbol.
const quietZone = 4

// SVG renders c as the Python release does (qrcode.image.svg.SvgPathImage
// with a box size of 10 and a border of 4): one millimetre per module and
// one path of unit squares in row order. The document contains only
// numbers derived from the matrix, so it is safe to embed.
func SVG(c *Code) string {
	side := strconv.Itoa(c.size + 2*quietZone)
	var b strings.Builder
	b.Grow(64 + 24*len(c.dark))
	b.WriteString("<?xml version='1.0' encoding='UTF-8'?>\n<svg width=\"")
	b.WriteString(side + "mm\" height=\"" + side + "mm\" version=\"1.1\" viewBox=\"0 0 " + side + " " + side)
	b.WriteString("\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"")
	for r := range c.size {
		for col := range c.size {
			if !c.dark[r*c.size+col] {
				continue
			}
			x0, y0 := strconv.Itoa(col+quietZone), strconv.Itoa(r+quietZone)
			x1, y1 := strconv.Itoa(col+quietZone+1), strconv.Itoa(r+quietZone+1)
			b.WriteString("M" + x0 + "," + y0 + "H" + x1 + "V" + y1 + "H" + x0 + "z")
		}
	}
	b.WriteString("\" id=\"qr-path\" fill=\"#000000\" fill-opacity=\"1\" fill-rule=\"nonzero\" stroke=\"none\" /></svg>")
	return b.String()
}
