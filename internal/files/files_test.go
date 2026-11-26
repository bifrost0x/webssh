package files_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

func TestClean(t *testing.T) {
	t.Parallel()
	ok := map[string]string{
		"/":          "/",
		"/a/b/":      "/a/b",
		"/a//b/./c":  "/a/b/c",
		`/a\b`:       `/a\b`,
		"/Grüße/漢字":  "/Grüße/漢字",
		"/a/.hidden": "/a/.hidden",
		"/" + strings.Repeat("x", files.MaxPathBytes-1): "/" + strings.Repeat("x", files.MaxPathBytes-1),
	}
	for in, want := range ok {
		if got, err := files.Clean(in); err != nil || got != want {
			t.Errorf("Clean(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", ".", "a/b", "/a/../b", "/..", "/a/..", "/a\x00b", "/a\nb", "/a\x7fb", "/a\u0085b",
		"/\xff", "/" + strings.Repeat("x", files.MaxPathBytes),
	}
	for _, in := range bad {
		if got, err := files.Clean(in); !fault.Is(err, fault.InvalidRequest) {
			t.Errorf("Clean(%q) = %q, %v; want invalid_request", in, got, err)
		}
	}
}

func TestCleanTarget(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"/", "//a", `/a\b`, "/a/../b", "/a/./.."} {
		if _, err := files.CleanTarget(in); err == nil {
			t.Errorf("CleanTarget(%q) accepted", in)
		}
	}
	if got, err := files.CleanTarget("/a/b/"); err != nil || got != "/a/b" {
		t.Errorf("CleanTarget = %q, %v", got, err)
	}
}

func TestValidNameAndJoin(t *testing.T) {
	t.Parallel()
	for _, n := range []string{"", ".", "..", "a/b", `a\b`, " \t", "a\x01", strings.Repeat("x", 256), "\xff"} {
		if files.ValidName(n) == nil {
			t.Errorf("ValidName(%q) accepted", n)
		}
	}
	for _, n := range []string{"a", ".env", "Grüße.txt", strings.Repeat("x", 255), " a "} {
		if err := files.ValidName(n); err != nil {
			t.Errorf("ValidName(%q): %v", n, err)
		}
	}
	if p, err := files.Join("/a", "b"); err != nil || p != "/a/b" {
		t.Errorf("Join = %q, %v", p, err)
	}
	if p, err := files.Join("/", "b"); err != nil || p != "/b" {
		t.Errorf("Join root = %q, %v", p, err)
	}
	if _, err := files.Join("/"+strings.Repeat("d", files.MaxPathBytes-3), "bb"); err == nil {
		t.Error("Join exceeded MaxPathBytes")
	}
}

func TestWithin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		root, p string
		fold    bool
		want    bool
	}{
		{"/", "/a", false, true},
		{"/a", "/a", false, true},
		{"/a", "/a/b", false, true},
		{"/a", "/ab", false, false},
		{"/a/b", "/a", false, false},
		{"/Docs", "/docs/x", true, true},
		{"/Docs", "/docs/x", false, false},
	}
	for _, c := range cases {
		if got := files.Within(c.root, c.p, c.fold); got != c.want {
			t.Errorf("Within(%q, %q, %v) = %v", c.root, c.p, c.fold, got)
		}
	}
}

// TestDecodeMatchesPython checks the decoding rule against vectors written
// by app/editor_text.py (decode_text, detect_newline).
func TestDecodeMatchesPython(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/decode-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Raw      string  `json:"raw"`
		Text     *string `json:"text"`
		Binary   bool    `json:"binary"`
		Encoding string  `json:"encoding"`
		Newline  string  `json:"newline"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for i, v := range vectors {
		raw, err := base64.StdEncoding.DecodeString(v.Raw)
		if err != nil {
			t.Fatal(err)
		}
		text, enc, binary := files.Decode(raw)
		want := ""
		if v.Text != nil {
			want = *v.Text
		}
		if binary != v.Binary || string(enc) != v.Encoding || text != want {
			t.Errorf("vector %d: Decode = %q, %q, %v; want %q, %q, %v", i, text, enc, binary, want, v.Encoding, v.Binary)
		}
		if got := files.DetectNewline(raw); string(got) != v.Newline {
			t.Errorf("vector %d: DetectNewline = %q, want %q", i, got, v.Newline)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", "a\r\nb", "\x00", "Gr\xfc\xdfe", "\xed\xa0\x80"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		text, enc, binary := files.Decode(raw)
		switch {
		case binary:
			if text != "" || enc != "" || !slices.Contains(raw[:min(len(raw), files.BinarySniffBytes)], 0) {
				t.Fatal("binary without a NUL in the sniffed prefix")
			}
		case enc == files.EncodingUTF8:
			if text != string(raw) {
				t.Fatal("UTF-8 text changed")
			}
		case enc == files.EncodingLatin1:
			if utf8.Valid(raw) || utf8.RuneCountInString(text) != len(raw) {
				t.Fatal("Latin-1 for valid UTF-8 or a length change")
			}
		default:
			t.Fatalf("encoding %q", enc)
		}
		// One pass as Python's str.replace: "\r\r\n" keeps one CR before
		// the LF, and no line break is lost or added.
		et := files.EditorText(text)
		if strings.Count(et, "\n") != strings.Count(text, "\n") || len(et) != len(text)-strings.Count(text, "\r\n") {
			t.Fatal("EditorText changed more than the CRLF pairs")
		}
	})
}

func TestRevision(t *testing.T) {
	t.Parallel()
	if got := files.Revision([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("Revision = %s", got)
	}
}

func TestSourceID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"sftp-session:abc", "sftp-quick:A_b-1", "smb-quick:" + strings.Repeat("f", 128)} {
		if _, _, err := files.ParseSourceID(id); err != nil {
			t.Errorf("ParseSourceID(%q): %v", id, err)
		}
	}
	for _, id := range []string{"", "sftp-session", "sftp-session:", "local:a", "smb-quick:_a", "smb-quick:a:b", "smb-quick:a.b", "smb-quick:" + strings.Repeat("f", 129)} {
		if _, _, err := files.ParseSourceID(id); !fault.Is(err, fault.SourceUnavailable) {
			t.Errorf("ParseSourceID(%q) = %v; want SOURCE_UNAVAILABLE", id, err)
		}
	}
	if id, err := files.FormatSourceID(files.SourceSMBQuick, "abc"); err != nil || id != "smb-quick:abc" {
		t.Errorf("FormatSourceID = %q, %v", id, err)
	}
}

func TestCapabilityNames(t *testing.T) {
	t.Parallel()
	want := []string{"list", "read", "write", "create-file", "mkdir", "rename", "delete", "preview", "edit", "recursive", "remote-transfer"}
	if got := files.CapAll.Names(); !slices.Equal(got, want) {
		t.Errorf("CapAll.Names() = %v", got)
	}
	if files.CapAll.Has(files.CapChmod) || !(files.CapAll | files.CapChmod).Has(files.CapChmod|files.CapList) {
		t.Error("Has is wrong")
	}
	if b := (files.Budget{}).WithDefaults(); b.MaxMembers != 10000 || b.MaxDepth != 50 {
		t.Errorf("Budget defaults = %+v", b)
	}
}

func FuzzClean(f *testing.F) {
	for _, s := range []string{"/", "/a/../b", "//a//b/", "/a/./b", `/a\b`, "/\x85"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := files.Clean(raw)
		if err != nil {
			return
		}
		again, err := files.Clean(p)
		if err != nil || again != p || p[0] != '/' || len(p) > files.MaxPathBytes {
			t.Fatalf("Clean(%q) = %q is not canonical", raw, p)
		}
		for seg := range strings.SplitSeq(p, "/") {
			if seg == ".." || seg == "." {
				t.Fatalf("Clean(%q) = %q keeps %q", raw, p, seg)
			}
		}
		if q, err := files.CleanTarget(raw); err == nil && (q != p || q == "/") {
			t.Fatalf("CleanTarget(%q) = %q, Clean = %q", raw, q, p)
		}
	})
}
