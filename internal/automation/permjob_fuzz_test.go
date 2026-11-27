package automation

import (
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
)

// The metadata token comes back from the page: no input other than a
// token this process issued for the same object verifies.
func FuzzPermissionMetadataToken(f *testing.F) {
	j, err := NewPermissionJobs(PermOptions{Sources: permSources{}, Now: func() time.Time { return time.Unix(1800000000, 0) }})
	if err != nil {
		f.Fatal(err)
	}
	c := PermCaller{P: principal.Principal{UserID: 1, SessionID: "s"}}
	snap := permSnapshot{Mode: "600", Size: 1, UID: -1, GID: -1}
	valid := j.metadataToken(c, "src", "/a", snap)
	f.Add(valid)
	f.Add("1800000000." + strings.Repeat("a", 64) + "." + strings.Repeat("b", 64))
	f.Add("")
	f.Add("..")
	f.Fuzz(func(t *testing.T, token string) {
		if j.verifyToken(token, c, "src", "/a", snap) == nil && token != valid {
			t.Fatalf("forged token %q verified", token)
		}
	})
}

func FuzzParseMode(f *testing.F) {
	for _, s := range []string{"644", "0644", "999", "", "7777", "६४४"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		m, err := ParseMode(s)
		if err != nil {
			return
		}
		if len(s) != 3 || m > 0o777 {
			t.Fatalf("%q parsed as %o", s, m)
		}
	})
}
