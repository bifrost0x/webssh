package github

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The redirect check reads administrator input and stored rows; it must
// never panic, and an accepted URI keeps the exact callback path.
func FuzzValidateRedirect(f *testing.F) {
	for _, s := range redirectInputs()[:60] {
		f.Add(s, "")
	}
	f.Add("https://[v1.x]/p/auth/github/callback", "/p")
	f.Fuzz(func(t *testing.T, uri, root string) {
		if validateRedirect(uri, root) != nil {
			return
		}
		u, err := pysplit(pyStrip(uri))
		if err != nil || u.path != strings.TrimRight(root, "/")+"/auth/github/callback" || u.hostname() == "" {
			t.Fatalf("accepted %q (root %q): %+v %v", uri, root, u, err)
		}
	})
}

// GitHub's profile answer is untrusted input.
func FuzzParseProfile(f *testing.F) {
	for _, r := range profileInputs() {
		f.Add(r.Body)
	}
	f.Fuzz(func(t *testing.T, body string) {
		p, err := parseProfile(200, []byte(body))
		if err != nil {
			return
		}
		if p.UserID == "" || p.UserID[0] == '0' || p.Login == "" || utf8.RuneCountInString(p.Login) > maxLoginChars ||
			utf8.RuneCountInString(p.DisplayName) > maxNameChars {
			t.Fatalf("accepted %q as %+v", body, p)
		}
	})
}

// Stored organization lists are read on every sign-in.
func FuzzStoredOrgs(f *testing.F) {
	for _, s := range []string{`[]`, `["a","b"]`, `"a,b"`, `[1]`, `{}`, `null`, `["` + strings.Repeat("a", 40) + `"]`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		orgs, err := storedOrgs(text)
		if err != nil {
			return
		}
		if len(orgs) > maxOrgs {
			t.Fatalf("%d organizations", len(orgs))
		}
		for _, o := range orgs {
			if !orgPattern.MatchString(o) {
				t.Fatalf("organization %q", o)
			}
		}
	})
}
