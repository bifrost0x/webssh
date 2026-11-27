package files_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// TestEncodeMatchesPython checks EncodeEditorText against vectors written
// by encode_editor_text of app/editor_text.py (testdata/oracle_editor.py):
// line endings, encodings, refused characters and the line alignment of
// files with mixed endings, including autojunk and the comparison bound.
func TestEncodeMatchesPython(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/encode-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Content  string  `json:"content"`
		Encoding string  `json:"encoding"`
		Newline  string  `json:"newline"`
		Original *string `json:"original"`
		Bytes    *string `json:"bytes"`
		Error    *struct {
			Character string `json:"character"`
			Line      int    `json:"line"`
			Value     bool   `json:"value"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 100 {
		t.Fatalf("only %d vectors", len(vectors))
	}
	for i, v := range vectors {
		var original []byte
		if v.Original != nil {
			if original, err = base64.StdEncoding.DecodeString(*v.Original); err != nil {
				t.Fatal(err)
			}
		}
		got, err := files.EncodeEditorText(v.Content, files.Encoding(v.Encoding), files.Newline(v.Newline), original)
		switch {
		case v.Error != nil && v.Error.Value:
			if !fault.Is(err, fault.InvalidRequest) {
				t.Errorf("vector %d: err = %v, want invalid_request", i, err)
			}
		case v.Error != nil:
			d := fault.DetailsOf(err)
			if !fault.Is(err, fault.EditEncodingUnsupported) || d["character"] != v.Error.Character || d["line"] != v.Error.Line {
				t.Errorf("vector %d: err = %v %v, want %q line %d", i, err, d, v.Error.Character, v.Error.Line)
			}
		default:
			want, _ := base64.StdEncoding.DecodeString(*v.Bytes)
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("vector %d (%s, %s): got %q, %v; want %q", i, v.Encoding, v.Newline, got, err, want)
			}
		}
	}
}

// TestEncodeMixedIsBounded: a crafted file with many lines saves quickly.
func TestEncodeMixedIsBounded(t *testing.T) {
	t.Parallel()
	var orig strings.Builder
	for i := range 40000 {
		orig.WriteString("x")
		if i%2 == 0 {
			orig.WriteString("\r\n")
		} else {
			orig.WriteString("\n")
		}
	}
	content := strings.Repeat("y\n", 40000)
	start := time.Now()
	if _, err := files.EncodeEditorText(content, files.EncodingUTF8, files.NewlineMixed, []byte(orig.String())); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("save took %v", d)
	}
}

// FuzzEditorRoundTrip: text opened in the editor and saved unchanged
// gives the same bytes. A lone CR is no line ending and the browser
// textarea turns it into LF anyway, so such files are left out (Python
// loses a CR before CRLF too).
func FuzzEditorRoundTrip(f *testing.F) {
	for _, s := range []string{"", "a\r\nb\n", "a\nb\r\nc", "Gr\xfc\xdfe\r\n", "x\ry\r\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		text, enc, binary := files.Decode(raw)
		if binary || bytes.Count(raw, []byte("\r")) != bytes.Count(raw, []byte("\r\n")) {
			return
		}
		nl := files.DetectNewline(raw)
		got, err := files.EncodeEditorText(files.EditorText(text), enc, nl, raw)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("round trip %q -> %q", raw, got)
		}
	})
}
