package hostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

func newKey(t testing.TB) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newStore(t testing.TB) (*Store, *store.DB) {
	t.Helper()
	db := storetest.Open(t, Schema())
	return New(db, nil), db
}

func importRaw(t *testing.T, db *store.DB, scope Scope, owner int64, raw string) {
	t.Helper()
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		return ImportFile(t.Context(), tx, scope, owner, []byte(raw), time.Now())
	}); err != nil {
		t.Fatal(err)
	}
}

// The trust-on-first-use contract of client.HostKeys: unknown is false
// without error, a recorded key is trusted for its owner only, a different
// key is refused without a prompt.
func TestKnownAndRecord(t *testing.T) {
	s, db := newStore(t)
	ctx := t.Context()
	first, other := newKey(t), newKey(t)
	if ok, err := s.Known(ctx, 1, "h.test", 2222, first); ok || err != nil {
		t.Fatalf("unknown host: %v, %v", ok, err)
	}
	if err := s.Record(ctx, 1, "h.test", 2222, first); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Known(ctx, 1, "h.test", 2222, first); !ok || err != nil {
		t.Fatalf("recorded key: %v, %v", ok, err)
	}
	if ok, err := s.Known(ctx, 1, "h.test", 2222, other); ok || !fault.Is(err, fault.HostKeyChanged) {
		t.Fatalf("other key: %v, %v", ok, err)
	}
	if ok, err := s.Known(ctx, 1, "h.test", 22, first); ok || err != nil {
		t.Fatalf("other port is another host: %v, %v", ok, err)
	}
	if ok, err := s.Known(ctx, 2, "h.test", 2222, first); ok || err != nil {
		t.Fatalf("another user has no trust: %v, %v", ok, err)
	}
	importRaw(t, db, ScopeGlobal, 0, "@revoked [h.test]:2222 "+first.Type()+" "+lineKey(first)+"\n")
	if ok, err := s.Known(ctx, 1, "h.test", 2222, first); ok || !fault.Is(err, fault.HostKeyRevoked) {
		t.Fatalf("globally revoked key: %v, %v", ok, err)
	}
	if err := s.Record(ctx, 2, "h.test", 2222, first); !fault.Is(err, fault.HostKeyRevoked) {
		t.Fatalf("recording a revoked key: %v", err)
	}
	if _, err := s.Known(ctx, 0, "h.test", 22, first); err == nil {
		t.Fatal("owner 0 accepted")
	}
}

func lineKey(k ssh.PublicKey) string {
	return strings.Fields(FormatLine("x", k))[2]
}

// Two sessions accept different keys for the same new host at the same
// time: exactly one wins, the other gets host_key_changed.
func TestRecordRace(t *testing.T) {
	s, _ := newStore(t)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() { errs[i] = s.Record(t.Context(), 1, "race.test", 22, newKey(t)) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !fault.Is(err, fault.HostKeyChanged):
			t.Fatalf("unexpected error: %v", err)
		}
	}
	entries, err := s.List(t.Context(), 1)
	if ok != 1 || err != nil || len(entries) != 1 {
		t.Fatalf("%d winners, %d entries, %v", ok, len(entries), err)
	}
}

// Kept from the Python release: one invalid line rejects the whole file and
// is named, at import and at run time.
func TestInvalidLineRejectsTheWholeFile(t *testing.T) {
	_, db := newStore(t)
	good := "h.test " + newKey(t).Type() + " " + lineKey(newKey(t)) + "\n"
	err := db.Write(t.Context(), func(tx *store.Tx) error {
		return ImportFile(t.Context(), tx, ScopeUser, 1, []byte(good+"bad.test ssh-dss AAAA\n"), time.Now())
	})
	var fe *InvalidFileError
	if !errors.As(err, &fe) || fe.Line != 2 || !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("import: %v", err)
	}

	s, db := newStore(t)
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		return writeFile(t.Context(), tx, ScopeGlobal, 0, []byte(good+"# c\n@foo x ssh-ed25519 AAAA\n"), time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { _, err := s.Known(t.Context(), 1, "h.test", 22, newKey(t)); return err },
		func() error { return s.Record(t.Context(), 1, "n.test", 22, newKey(t)) },
		func() error { _, err := s.Effective(t.Context(), 1, nil); return err },
	} {
		err := call()
		status, code, message := fault.Status(err)
		if code != fault.StorageError || status != 500 || !strings.Contains(message, "line 3 of the global known hosts") {
			t.Errorf("got %d %s %q", status, code, message)
		}
	}
}

func TestImportFileValidatesScope(t *testing.T) {
	_, db := newStore(t)
	for _, c := range []struct {
		scope Scope
		owner int64
	}{{ScopeGlobal, 1}, {ScopeUser, 0}, {"other", 1}, {ScopeUser, -1}} {
		err := db.Write(t.Context(), func(tx *store.Tx) error {
			return ImportFile(t.Context(), tx, c.scope, c.owner, nil, time.Now())
		})
		if err == nil {
			t.Errorf("%s/%d accepted", c.scope, c.owner)
		}
	}
	importRaw(t, db, ScopeUser, 1, "")
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		return ImportFile(t.Context(), tx, ScopeUser, 1, nil, time.Now())
	}); err == nil {
		t.Error("second import accepted")
	}
}

func TestPreferredPutsTrustedTypesFirst(t *testing.T) {
	s, db := newStore(t)
	importRaw(t, db, ScopeGlobal, 0, "rsa.test ssh-rsa "+rsaKeyBase64(t)+"\n")
	allowed := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	got, err := s.Preferred(t.Context(), 1, "rsa.test", 22, allowed)
	if err != nil || got[0] != ssh.KeyAlgoRSASHA512 || got[1] != ssh.KeyAlgoRSASHA256 || len(got) != len(allowed) {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, _ := s.Preferred(t.Context(), 1, "new.test", 22, allowed); got[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("unknown host: %v", got)
	}
}

func rsaKeyBase64(t *testing.T) string {
	t.Helper()
	return loadOracle(t).Keys["rsaD"].Base64
}

func TestDeleteChecksRevision(t *testing.T) {
	s, db := newStore(t)
	k := newKey(t)
	importRaw(t, db, ScopeUser, 1, "a.test "+k.Type()+" "+lineKey(k)+"\nb.test "+k.Type()+" "+lineKey(k)+"\n")
	entries, _ := s.List(t.Context(), 1)
	impact, err := s.DeletionImpact(t.Context(), 1, entries[0].ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Trust changes after the preview: the stale revision is refused.
	if err := s.Record(t.Context(), 1, "c.test", 22, k); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(t.Context(), 1, entries[0].ID, impact.Revision, true); !fault.Is(err, fault.PreconditionFailed) {
		t.Fatalf("stale revision: %v", err)
	}
	impact, _ = s.DeletionImpact(t.Context(), 1, entries[0].ID, nil)
	if err := s.Delete(t.Context(), 1, entries[0].ID, impact.Revision, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(t.Context(), 1, entries[0].ID, "", false); !fault.Is(err, fault.NotFound) {
		t.Fatalf("second delete: %v", err)
	}
	other := New(db, nil)
	impact, _ = s.DeletionImpact(t.Context(), 1, entries[1].ID, nil)
	if err := other.Delete(t.Context(), 1, entries[1].ID, impact.Revision, true); !fault.Is(err, fault.PreconditionFailed) {
		t.Fatalf("a revision is valid in its process only: %v", err)
	}
	if _, err := s.DeletionImpact(t.Context(), 2, entries[1].ID, nil); !fault.Is(err, fault.NotFound) {
		t.Fatalf("another user's entry: %v", err)
	}
}

func TestPythonISOTime(t *testing.T) {
	for in, want := range map[time.Time]string{
		time.Date(2026, 11, 26, 7, 38, 39, 0, time.UTC):                 "2026-11-26T07:38:39+00:00",
		time.Date(2026, 11, 26, 7, 38, 39, 123456789, time.UTC):         "2026-11-26T07:38:39.123456+00:00",
		time.Date(2026, 1, 2, 3, 4, 5, 1000, time.FixedZone("x", 3600)): "2026-01-02T02:04:05.000001+00:00",
	} {
		if got := pythonISOTime(in); got != want {
			t.Errorf("%v: %s, want %s", in, got, want)
		}
	}
}

func TestHostPortUnicodeDigits(t *testing.T) {
	for in, want := range map[string]struct {
		host string
		port int
	}{
		"[h]:2222":                    {"h", 2222},
		"[h]:٢٢":                      {"h", 22},
		"[a]:1]:22":                   {"a]:1", 22},
		"[h]:x":                       {"[h]:x", 22},
		"[]:22":                       {"[]:22", 22},
		"[h]:":                        {"[h]:", 22},
		"h":                           {"h", 22},
		"[h]:99999999999999999999999": {"[h]:99999999999999999999999", 22},
	} {
		if h, p := HostPort(in); h != want.host || p != want.port {
			t.Errorf("%q: %q %d", in, h, p)
		}
	}
}
