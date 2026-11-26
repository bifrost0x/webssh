package hostkey

import (
	"encoding/base64"
	"errors"
	"strings"
)

var errBase64 = errors.New("invalid base64 key data")

// decodeBase64Lenient reproduces Python's base64.decodebytes, which paramiko
// used for the key column: characters outside the alphabet are skipped,
// padding counts only after the last data character, and the data characters
// are decoded as one stream.
func decodeBase64Lenient(text string) ([]byte, error) {
	var data strings.Builder
	pads := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '=':
			pads++
		case isBase64Char(c):
			data.WriteByte(c)
			pads = 0
		}
	}
	switch data.Len() % 4 {
	case 1:
		return nil, errBase64
	case 2:
		if pads < 2 {
			return nil, errBase64
		}
	case 3:
		if pads < 1 {
			return nil, errBase64
		}
	}
	out, err := base64.RawStdEncoding.DecodeString(data.String())
	if err != nil {
		return nil, errBase64
	}
	return out, nil
}

func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}
