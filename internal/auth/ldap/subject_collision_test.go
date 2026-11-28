package ldap

import (
	"context"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ldapproto"
)

// Two objectGUID values that start with an ASCII digit and NUL were the
// same subject "7" in the Python release (the C string up to the NUL read
// as an integer). New identities use the whole value; a binding stored
// under the truncated form is used only by the entry it was recorded for.
func TestObjectGUIDSubjectsAreDistinct(t *testing.T) {
	t.Parallel()
	c := &Client{s: Settings{UniqueIDAttribute: "objectGUID"}}
	guidA := []byte{'7', 0x00, 0x9a, 0x13, 0xc4, 0x51, 0x4e, 0x47, 0x9b, 0x22, 0x10, 0xfe, 0x8d, 0x3a, 0x6b, 0x01}
	guidB := []byte{'7', 0x00, 0x11, 0xee, 0x02, 0x7c, 0x4d, 0x4a, 0x81, 0x9f, 0x55, 0x0b, 0xc3, 0x2e, 0x90, 0xaa}
	entry := func(dn string, guid []byte) Entry {
		e, err := c.entry(ldapproto.Entry{DN: dn, Attributes: map[string][][]byte{"objectGUID": {guid}}})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	ea, eb := entry("uid=alice,dc=example", guidA), entry("uid=mallory,dc=example", guidB)
	if ea.Subject == eb.Subject {
		t.Fatalf("both entries have subject %q", ea.Subject)
	}

	for _, stored := range []string{ea.Subject, "7"} {
		f := newFixture(t)
		f.linkUser(t, 7, "alice", stored, "pw-alice")
		f.dir.mu.Lock()
		f.dir.entries["alice"] = ea
		f.dir.entries["mallory"] = eb
		f.dir.passwords[eb.DN] = "pw-mallory"
		f.dir.mu.Unlock()
		if id, err := f.svc.Authenticate(t.Context(), "mallory", "pw-mallory"); err == nil || id == 7 {
			t.Fatalf("stored %q: mallory signed in to account %d (%v)", stored, id, err)
		}
		if id, err := f.svc.Authenticate(t.Context(), "alice", "pw-alice"); err != nil || id != 7 {
			t.Fatalf("stored %q: alice: %d %v", stored, id, err)
		}
		// Alice's sign-in moved a truncated binding to the whole value;
		// mallory still gets no access to it.
		row, _, _ := f.svc.IdentityOf(t.Context(), 7)
		if row.Subject != ea.Subject || row.DirectoryUsername != "alice" {
			t.Fatalf("stored %q: identity now %+v", stored, row)
		}
		if id, err := f.svc.Authenticate(t.Context(), "mallory", "pw-mallory"); err == nil || id == 7 {
			t.Fatalf("stored %q: mallory after upgrade: %d %v", stored, id, err)
		}
	}
}

// A binding the Python release stored under the truncated subject keeps
// passing revalidation and step-up for the entry it was recorded for.
func TestLegacyTruncatedSubjectStillChecks(t *testing.T) {
	t.Parallel()
	c := &Client{s: Settings{UniqueIDAttribute: "objectGUID"}}
	guid := []byte{'7', 0x00, 0x9a, 0x13, 0xc4, 0x51, 0x4e, 0x47, 0x9b, 0x22, 0x10, 0xfe, 0x8d, 0x3a, 0x6b, 0x01}
	ea, err := c.entry(ldapproto.Entry{DN: "uid=alice,dc=example", Attributes: map[string][][]byte{"objectGUID": {guid}}})
	if err != nil || ea.LegacySubject != "7" {
		t.Fatalf("%+v %v", ea, err)
	}
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "7", "pw-alice")
	f.dir.mu.Lock()
	f.dir.entries["alice"] = ea
	f.dir.mu.Unlock()
	if err := f.svc.Revalidate(t.Context(), 7); err != nil {
		t.Fatalf("revalidation: %v", err)
	}
	if ok, err := f.svc.VerifyStepUp(t.Context(), 7, "pw-alice"); err != nil || !ok {
		t.Fatalf("step-up: %v %v", ok, err)
	}
}

// The directory matches spellings of a name that the name ceiling counts
// apart (full-width, mathematical letters); the attempts of one directory
// entry are counted together whatever the spelling.
func TestAttemptsCountedPerDirectoryEntry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-alice")
	f.dir.mu.Lock()
	for _, v := range []string{"ａｌｉｃｅ", "\U0001d41alice"} {
		f.dir.entries[v] = f.dir.entries["alice"]
	}
	f.dir.mu.Unlock()
	var mu sync.Mutex
	held := map[string]int{}
	f.svc.Attempts = func(_ context.Context, subject string) (func(), bool) {
		mu.Lock()
		defer mu.Unlock()
		if held[subject] >= 3 {
			return nil, false
		}
		held[subject]++
		return func() { mu.Lock(); held[subject]--; mu.Unlock() }, true
	}
	for i, name := range []string{"alice", "ａｌｉｃｅ", "\U0001d41alice"} {
		if _, err := f.svc.Authenticate(t.Context(), name, "wrong"); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := f.svc.Authenticate(t.Context(), "ａｌｉｃｅ", "pw-alice"); !fault.Is(err, fault.RateLimited) {
		t.Fatalf("fourth spelling passed the ceiling: %v", err)
	}
	if held["corp\x00uuid-a"] != 3 {
		t.Fatalf("held %v", held)
	}
}
