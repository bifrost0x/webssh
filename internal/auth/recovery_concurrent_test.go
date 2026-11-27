package auth

import (
	"sync"
	"sync/atomic"
	"testing"
)

// One recovery code redeemed by concurrent requests succeeds once.
func TestRecoveryConcurrentConsume(t *testing.T) {
	t.Parallel()
	rc := &Recovery{DB: openDB(t), iterations: 1}
	codes, err := rc.Generate(t.Context(), 9)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			code := codes[0]
			if i%2 == 1 {
				code = " " + string([]byte(code)) + "\t" // normalised form
			}
			ok, err := rc.Consume(t.Context(), 9, code)
			if err != nil {
				t.Error(err)
			}
			if ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if n := wins.Load(); n != 1 {
		t.Fatalf("code accepted %d times", n)
	}
	if ok, _ := rc.Consume(t.Context(), 10, codes[1]); ok {
		t.Fatal("another account's code accepted")
	}
}
