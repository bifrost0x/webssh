package local

import (
	"context"
	json "encoding/json/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

var testParams = Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

func testHasher(t testing.TB) *Hasher {
	t.Helper()
	h, err := NewHasher(testParams, 2)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type vector struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
}

func vectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/python_bcrypt.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

// Every bcrypt hash of the golden fixture verifies with its password and
// asks for a rehash; the 72-byte password verifies, 73 bytes do not.
func TestPythonBcryptHashes(t *testing.T) {
	t.Parallel()
	h := testHasher(t)
	var saw72 bool
	for _, v := range vectors(t) {
		ok, rehash, err := h.Verify(t.Context(), AlgorithmBcrypt, v.Hash, v.Password)
		if err != nil || !ok || !rehash {
			t.Errorf("%s: ok=%v rehash=%v err=%v", v.Username, ok, rehash, err)
		}
		if ok, _, _ := h.Verify(t.Context(), AlgorithmBcrypt, v.Hash, v.Password+"x"); ok {
			t.Errorf("%s: wrong password accepted", v.Username)
		}
		if len(v.Password) == 72 {
			saw72 = true
			if ok, _, _ := h.Verify(t.Context(), AlgorithmBcrypt, v.Hash, v.Password+"!"); ok {
				t.Error("73-byte password matched a bcrypt hash")
			}
		}
	}
	if !saw72 {
		t.Fatal("fixture lacks the 72-byte password")
	}
}

func TestArgon2RoundTripAndRehash(t *testing.T) {
	t.Parallel()
	h := testHasher(t)
	hash, err := h.Hash(t.Context(), "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("hash %q", hash)
	}
	if ok, rehash, err := h.Verify(t.Context(), AlgorithmArgon2id, hash, "correct horse"); !ok || rehash || err != nil {
		t.Fatalf("ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if ok, _, _ := h.Verify(t.Context(), AlgorithmArgon2id, hash, "correct horsf"); ok {
		t.Fatal("wrong password accepted")
	}
	stronger := testParams
	stronger.Time = 2
	h2, err := NewHasher(stronger, 1)
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, _ := h2.Verify(t.Context(), AlgorithmArgon2id, hash, "correct horse"); !ok || !rehash {
		t.Fatal("weaker parameters not rehashed")
	}
	// 1024 bytes is allowed, 1025 refused before hashing.
	long := strings.Repeat("ä", 512)
	if _, err := h.Hash(t.Context(), long); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Hash(t.Context(), long+"x"); err != ErrTooLong {
		t.Fatalf("1025 bytes: %v", err)
	}
	if ok, _, _ := h.Verify(t.Context(), AlgorithmArgon2id, hash, long+"x"); ok {
		t.Fatal("over-long password verified")
	}
}

func TestMalformedHashesFailClosed(t *testing.T) {
	t.Parallel()
	h := testHasher(t)
	good, _ := h.Hash(t.Context(), "password1")
	bad := []struct{ alg, hash string }{
		{"md5", good},
		{AlgorithmArgon2id, ""},
		{AlgorithmArgon2id, strings.Replace(good, "argon2id", "argon2i", 1)},
		{AlgorithmArgon2id, strings.Replace(good, "v=19", "v=16", 1)},
		{AlgorithmArgon2id, strings.Replace(good, "m=64", "m=9999999", 1)},
		{AlgorithmArgon2id, strings.Replace(good, "t=1", "t=0", 1)},
		{AlgorithmArgon2id, strings.Replace(good, "p=1", "p=200", 1)},
		{AlgorithmArgon2id, strings.Replace(good, "m=64", "m=064", 1)},
		{AlgorithmArgon2id, good + "$"},
		{AlgorithmArgon2id, good + "="},
		{AlgorithmBcrypt, good},
		{AlgorithmBcrypt, "$2x$12$" + strings.Repeat("a", 53)},
		{AlgorithmBcrypt, "$2b$99$" + strings.Repeat("a", 53)},
		{AlgorithmBcrypt, "$2b$12$" + strings.Repeat("!", 53)},
	}
	for _, b := range bad {
		if ok, _, err := h.Verify(t.Context(), b.alg, b.hash, "password1"); ok || err != ErrFormat {
			t.Errorf("%s %q: ok=%v err=%v", b.alg, b.hash, ok, err)
		}
	}
}

func TestNewHasherRejectsWeakParams(t *testing.T) {
	t.Parallel()
	for _, p := range []Params{
		{Memory: 64, Time: 0, Threads: 1, KeyLen: 32, SaltLen: 16},
		{Memory: 64, Time: 1, Threads: 1, KeyLen: 8, SaltLen: 16},
		{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 4},
		{Memory: 1 << 30, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
	} {
		if _, err := NewHasher(p, 1); err == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	if _, err := NewHasher(DefaultParams, 0); err != nil {
		t.Fatal(err)
	}
}

// No more than the configured number of hashes run at once, and waiting
// ends with the context.
func TestConcurrencyBound(t *testing.T) {
	t.Parallel()
	h := testHasher(t) // 2 slots
	h.slots <- struct{}{}
	h.slots <- struct{}{}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "password1"); err == nil {
		t.Fatal("hash ran beyond the bound")
	}
	<-h.slots
	<-h.slots
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := h.acquire(t.Context()); err != nil {
				t.Error(err)
				return
			}
			n := running.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			running.Add(-1)
			h.release()
		})
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Fatalf("peak %d", peak.Load())
	}
}

type fakeAccounts map[string]struct {
	id     int64
	usable bool
}

func (f fakeAccounts) SignInStanding(_ context.Context, name string) (int64, bool, error) {
	a := f[name]
	return a.id, a.usable, nil
}

func providerWith(t *testing.T, accounts fakeAccounts) *Provider {
	t.Helper()
	return &Provider{DB: storetest.Open(t, Schema()), Accounts: accounts, Hasher: testHasher(t)}
}

func insertRaw(t *testing.T, p *Provider, id int64, alg, hash string) {
	t.Helper()
	err := p.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO authlocal_passwords VALUES (?, ?, ?, 0)`, id, alg, hash)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readRow(t *testing.T, p *Provider, id int64) stored {
	t.Helper()
	s, _, err := p.read(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A migrated bcrypt account signs in, its row becomes Argon2id and the
// password still verifies; wrong, unknown, locked and managed accounts
// all fail alike.
func TestAuthenticate(t *testing.T) {
	t.Parallel()
	v := vectors(t)[0]
	acc := fakeAccounts{
		"alice":  {1, true},
		"locked": {2, false},
		"nohash": {3, true},
	}
	p := providerWith(t, acc)
	insertRaw(t, p, 1, AlgorithmBcrypt, v.Hash)
	insertRaw(t, p, 2, AlgorithmBcrypt, v.Hash)

	id, err := p.Authenticate(t.Context(), "alice", v.Password)
	if err != nil || id != 1 {
		t.Fatalf("id=%d err=%v", id, err)
	}
	if row := readRow(t, p, 1); row.algorithm != AlgorithmArgon2id {
		t.Fatalf("not rehashed: %+v", row)
	}
	if _, err := p.Authenticate(t.Context(), "alice", v.Password); err != nil {
		t.Fatalf("after rehash: %v", err)
	}
	for _, c := range []struct{ name, pw string }{
		{"alice", "wrong"}, {"Alice", v.Password}, {"nobody", v.Password},
		{"locked", v.Password}, {"nohash", v.Password}, {"alice", strings.Repeat("a", 1025)},
		{"alice", "\xff\xfe"},
	} {
		_, err := p.Authenticate(t.Context(), c.name, c.pw)
		if fault.CodeOf(err) != fault.AuthFailed {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, _, msg := fault.Status(err); msg != "Invalid username or password" {
			t.Errorf("%s: message %q", c.name, msg)
		}
	}
	if ok, err := p.Matches(t.Context(), 1, v.Password); !ok || err != nil {
		t.Fatalf("Matches: %v %v", ok, err)
	}
	if ok, _ := p.Matches(t.Context(), 3, v.Password); ok {
		t.Fatal("Matches without a row")
	}
}

func TestStoreTxRefusesNonArgon2(t *testing.T) {
	t.Parallel()
	p := providerWith(t, nil)
	err := p.DB.Write(t.Context(), func(tx *store.Tx) error {
		return p.StoreTx(t.Context(), tx, 1, vectors(t)[0].Hash)
	})
	if err == nil {
		t.Fatal("stored a bcrypt hash as new password")
	}
	hash, _ := p.Hash(t.Context(), "password1")
	if err := p.DB.Write(t.Context(), func(tx *store.Tx) error { return p.StoreTx(t.Context(), tx, 1, hash) }); err != nil {
		t.Fatal(err)
	}
	if err := p.DB.Write(t.Context(), func(tx *store.Tx) error { return p.StoreTx(t.Context(), tx, 1, hash) }); err != nil {
		t.Fatalf("replace: %v", err)
	}
}

func TestValidateNew(t *testing.T) {
	t.Parallel()
	for pw, want := range map[string]string{
		"1234567":                 "Password must be at least 8 characters",
		"ääääääää":                "",
		"12345678":                "",
		strings.Repeat("a", 1024): "",
		strings.Repeat("a", 1025): "Password must not exceed 1024 bytes when encoded as UTF-8",
		"12345678\xff":            "Password must not exceed 1024 bytes when encoded as UTF-8",
		strings.Repeat("ä", 40):   "", // 80 bytes: above bcrypt's 72, allowed now (D-12)
	} {
		if got := ValidateNew(pw); got != want {
			t.Errorf("%q: %q, want %q", pw, got, want)
		}
	}
}

func FuzzParseArgon2(f *testing.F) {
	h, _ := NewHasher(testParams, 1)
	good, _ := h.Hash(context.Background(), "x")
	f.Add(good)
	f.Add("$argon2id$v=19$m=1,t=1,p=1$$")
	f.Fuzz(func(t *testing.T, s string) {
		p, salt, key, err := parseArgon2(s)
		if err != nil {
			return
		}
		if p.Memory > maxMemory || p.Time > maxTime || p.Threads > maxThreads || len(salt) > 64 || len(key) > 64 {
			t.Fatalf("bounds not enforced: %+v", p)
		}
	})
}

// Rough cost of the default parameters, for the report:
// go test -run x -bench Argon2Default ./internal/auth/local
func BenchmarkArgon2Default(b *testing.B) {
	h, err := NewHasher(DefaultParams, 1)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := h.Hash(b.Context(), "benchmark password"); err != nil {
			b.Fatal(err)
		}
	}
}

// Unknown names and over-long passwords against bcrypt accounts spend a
// real bcrypt computation while bcrypt hashes remain.
func TestLegacyTimingPaths(t *testing.T) {
	t.Parallel()
	v := vectors(t)[0]
	p := providerWith(t, fakeAccounts{"alice": {1, true}})
	insertRaw(t, p, 1, AlgorithmBcrypt, v.Hash)
	if !p.legacyHashes(t.Context()) {
		t.Fatal("bcrypt rows not seen")
	}
	start := time.Now()
	_, err := p.Authenticate(t.Context(), "nobody", "password1")
	if fault.CodeOf(err) != fault.AuthFailed || time.Since(start) < 50*time.Millisecond {
		t.Fatalf("unknown name answered in %v (%v)", time.Since(start), err)
	}
	start = time.Now()
	_, err = p.Authenticate(t.Context(), "alice", strings.Repeat("a", 73))
	if fault.CodeOf(err) != fault.AuthFailed || time.Since(start) < 50*time.Millisecond {
		t.Fatalf("73-byte password answered in %v (%v)", time.Since(start), err)
	}
	if p.Hasher.legacyDummy == "" {
		t.Fatal("no legacy dummy")
	}
}
