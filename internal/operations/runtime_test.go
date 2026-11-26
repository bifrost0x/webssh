package operations

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Values of hashlib.sha256((prefix + id).encode('utf-8')).hexdigest(),
// computed with Python 3 (app/operations.py).
func TestReferencesMatchPython(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ got, want string }{
		{ConnectionRef("abc"), "96c74afedc3e23840849e25582ce3772d4f67f8ee22aa13043d292e5a116f664"},
		{SessionRef("abc"), "8a0949875362467f4d2a987e8286f7f88b2aed88b0833f3fd2bec2a7b8827848"},
		{ConnectionRef("ünï"), "2740a3a061acbd052eebe7195d0a355f0be49bab8da7bf75479f351293425c77"},
		{SessionRef(""), "d6afff13ce3fd507ea8390928e2f6d0f0ed2c80b0ef141f6e4ce47848f6a4d6a"},
	} {
		if c.got != c.want {
			t.Errorf("reference %s, want %s", c.got, c.want)
		}
	}
}

func TestSupportRequest(t *testing.T) {
	t.Parallel()
	r := SupportRequest{}
	if err := r.Validate(); err != nil || r.Area != "general" {
		t.Fatalf("default: %+v %v", r, err)
	}
	ok := SupportRequest{Area: "files", Reference: "SMB-0123456789AB"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []SupportRequest{
		{Area: "logs"}, {Area: "files", Reference: "SMB-0123456789ab"},
		{Reference: "SMB-0123456789AB\n"}, {Reference: "smb-0123456789AB"}, {Reference: "SMB-0123"},
	} {
		if err := bad.Validate(); !fault.Is(err, fault.InvalidRequest) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}
