package local

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// While one bcrypt hash remains, an unknown name, a bcrypt account and an
// account already rehashed to Argon2id must answer a wrong password in
// about the same time, so the answer time does not tell which names
// exist (RS2-08).
func TestFailedSignInTimingIndependentOfHash(t *testing.T) {
	v := vectors(t)[0]
	h, err := NewHasher(DefaultParams, 2)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{DB: storetest.Open(t, Schema()), Accounts: fakeAccounts{"alice": {1, true}, "bob": {2, true}}, Hasher: h}
	insertRaw(t, p, 1, AlgorithmBcrypt, v.Hash)
	argon, _ := h.Hash(t.Context(), "correct-horse")
	insertRaw(t, p, 2, AlgorithmArgon2id, argon)
	measure := func(name string) time.Duration {
		best := time.Hour
		for range 5 {
			start := time.Now()
			_, _ = p.Authenticate(t.Context(), name, "wrong-password")
			best = min(best, time.Since(start))
		}
		return best
	}
	unknown, rehashed, legacy := measure("nobody"), measure("bob"), measure("alice")
	t.Logf("unknown name %v, Argon2id account %v, bcrypt account %v", unknown, rehashed, legacy)
	for _, d := range []time.Duration{rehashed, legacy} {
		if unknown > 2*d || d > 2*unknown {
			t.Fatalf("unknown name %v, Argon2id account %v, bcrypt account %v: the name is distinguishable", unknown, rehashed, legacy)
		}
	}
}
