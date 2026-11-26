package sftp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

var testLimits = limits{maxName: DefaultMaxNameBytes, maxHandle: DefaultMaxHandleBytes, maxMetadata: DefaultMaxMetadataBytes}

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func str(b []byte) []byte { return append(be32(uint32(len(b))), b...) }

func ext(n int, size int) []byte {
	out := be32(attrExtended)
	out = append(out, be32(uint32(n))...)
	for range n {
		out = append(out, str(bytes.Repeat([]byte("x"), size))...)
		out = append(out, str(nil)...)
	}
	return out
}

func TestAttributeBounds(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		ok   bool
	}{
		{"empty", be32(0), true},
		{"all fields", append(be32(attrSize|attrUIDGID|attrPermissions|attrACModTime), make([]byte, 8+8+4+8)...), true},
		{"unknown flag", be32(0x10), false},
		{"truncated size", append(be32(attrSize), 1, 2), false},
		{"16 extensions", ext(16, 1), true},
		{"17 extensions", ext(17, 1), false},
		{"extension name at limit", ext(1, DefaultMaxNameBytes), true},
		{"extension name over limit", ext(1, DefaultMaxNameBytes+1), false},
		{"extension bytes over 64 KiB", ext(16, 4096+1), false},
		{"trailing byte", append(be32(0), 0), false},
	}
	for _, c := range cases {
		if got := validateReply(fxpAttrs, c.body, testLimits) == nil; got != c.ok {
			t.Errorf("%s: accepted %v, want %v", c.name, got, c.ok)
		}
	}
}

func TestNameAndHandleBounds(t *testing.T) {
	entry := func(name []byte) []byte {
		return append(append(str(name), str(nil)...), be32(0)...)
	}
	one := append(be32(1), entry([]byte("a"))...)
	if validateReply(fxpName, one, testLimits) != nil {
		t.Fatal("valid NAME refused")
	}
	if validateReply(fxpName, be32(0), testLimits) == nil {
		t.Error("empty NAME accepted")
	}
	if validateReply(fxpName, append(be32(1000), entry([]byte("a"))...), testLimits) == nil {
		t.Error("count beyond the packet accepted")
	}
	long := append(be32(1), entry(bytes.Repeat([]byte("n"), DefaultMaxNameBytes+1))...)
	if validateReply(fxpName, long, testLimits) == nil {
		t.Error("oversized name accepted")
	}
	if validateReply(fxpHandle, str(nil), testLimits) == nil {
		t.Error("empty handle accepted")
	}
	if validateReply(fxpHandle, str(make([]byte, DefaultMaxHandleBytes+1)), testLimits) == nil {
		t.Error("oversized handle accepted")
	}
	if validateReply(77, nil, testLimits) == nil {
		t.Error("unknown reply type accepted")
	}
}

func TestVersionExtensions(t *testing.T) {
	pair := func(n, d string) []byte { return append(str([]byte(n)), str([]byte(d))...) }
	body := append(append(be32(3), pair(extPosixRename, "1")...), pair(extLsetstat, "1")...)
	_, e, err := parseVersion(body)
	if err != nil || e[extPosixRename] != "1" || e[extLsetstat] != "1" {
		t.Fatalf("%v %v", e, err)
	}
	conflict := append(append(be32(3), pair("a@x", "1")...), pair("a@x", "2")...)
	if _, e, _ := parseVersion(conflict); len(e) != 0 {
		t.Errorf("conflicting duplicate kept: %v", e)
	}
	if _, e, _ := parseVersion(append(be32(4), pair("a@x", "1")...)); len(e) != 0 {
		t.Errorf("extensions of version 4 kept: %v", e)
	}
	if _, _, err := parseVersion([]byte{0, 0}); err == nil {
		t.Error("short version accepted")
	}
}

func FuzzValidateReply(f *testing.F) {
	f.Add(byte(fxpAttrs), ext(2, 3))
	f.Add(byte(fxpName), append(be32(1), append(append(str([]byte("a")), str(nil)...), be32(0)...)...))
	f.Add(byte(fxpStatus), append(be32(2), append(str([]byte("m")), str(nil)...)...))
	f.Add(byte(fxpVersion), be32(3))
	f.Fuzz(func(t *testing.T, typ byte, body []byte) {
		if typ == fxpVersion {
			_, _, _ = parseVersion(body)
			return
		}
		if validateReply(typ, body, testLimits) != nil {
			return
		}
		// What passes is safe to decode again.
		d := &decoder{b: body}
		switch typ {
		case fxpName:
			for _, e := range d.names(testLimits) {
				if len(e.name) > testLimits.maxName {
					t.Fatal("name over the limit")
				}
			}
		case fxpAttrs:
			if a := d.attrs(testLimits); a.extensions > maxAttrExtensionBytes {
				t.Fatal("extensions over the limit")
			}
		}
	})
}
