package hostkey

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte("h.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOL2WzJx0sV/B6VxWU9MnxKJFrrYYNJle330w6TBemSK\n"))
	f.Add([]byte("@revoked *.t,!x.t ssh-rsa AAAA\r\n# c\n|1|AAAA|BBBB ssh-ed25519 AAAA"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		file, err := Parse(raw)
		if err != nil {
			return
		}
		trust := Trust{User: file}
		for _, e := range file.Trusted {
			for _, p := range e.Patterns {
				_ = trust.Lookup(p)
				_ = trust.Verify(p, e.Key)
			}
		}
		// Trust and listing see the same lines.
		listed, err := List(raw, ScopeUser, "1")
		if err != nil || len(listed) != len(file.Trusted)+len(file.Revoked)+len(file.CertAuthorities) {
			t.Fatalf("parse accepts, list: %d entries, %v", len(listed), err)
		}
	})
}

func FuzzGlob(f *testing.F) {
	f.Add("*.lab.test", "a.lab.test")
	f.Add("db?.x", "DB1.X")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		_ = globFold(pattern, name)
	})
}

// An accepted global entry is one line that parses back to the same entry
// and never carries the @cert-authority marker.
func FuzzCanonicalEntry(f *testing.F) {
	f.Add("h.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOL2WzJx0sV/B6VxWU9MnxKJFrrYYNJle330w6TBemSK comment")
	f.Add("@revoked [h.test]:22,!x ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOL2WzJx0sV/B6VxWU9MnxKJFrrYYNJle330w6TBemSK")
	f.Fuzz(func(t *testing.T, value string) {
		line, entry, err := canonicalEntry(value)
		if err != nil {
			return
		}
		if entry.Marker == MarkerCertAuthority {
			t.Fatalf("accepted a certificate authority: %q", value)
		}
		file, err := Parse([]byte(line + "\n"))
		if err != nil || len(file.Trusted)+len(file.Revoked) != 1 {
			t.Fatalf("canonical line %q does not parse back: %v", line, err)
		}
	})
}
