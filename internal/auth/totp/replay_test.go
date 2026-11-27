package totp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// A code accepted for the sign-in cannot be replayed as a
// step-up proof within its window, and vice versa.
func TestTOTPReplayAcrossScopes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	secret, _ := e.enrol(t, principaltest.User(11))
	e.clock.Advance(time.Minute)
	code := e.codeAt(t, secret, 0)
	if err := e.svc.CheckCode(ctx, 11, code, auth.ScopeLogin); err != nil {
		t.Fatalf("sign-in code: %v", err)
	}
	if err := e.svc.CheckCode(ctx, 11, code, auth.ScopeStepUp); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("sign-in code replayed as step-up: %v", err)
	}
	e.clock.Advance(time.Minute)
	code = e.codeAt(t, secret, 0)
	if err := e.svc.CheckCode(ctx, 11, code, auth.ScopeStepUp); err != nil {
		t.Fatalf("step-up code: %v", err)
	}
	for _, scope := range []auth.Scope{auth.ScopeStepUp, auth.ScopeLogin} {
		if err := e.svc.CheckCode(ctx, 11, code, scope); !fault.Is(err, fault.AuthFailed) {
			t.Fatalf("step-up code replayed in %s: %v", scope, err)
		}
	}
	// An older step in the skew window is a replay too.
	if err := e.svc.CheckCode(ctx, 11, e.codeAt(t, secret, -1), auth.ScopeStepUp); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("previous step accepted after a newer one: %v", err)
	}
}

// Concurrent requests with one code: exactly one wins.
func TestTOTPConcurrentReplay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	secret, _ := e.enrol(t, principaltest.User(12))
	e.clock.Advance(time.Minute)
	code := e.codeAt(t, secret, 0)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			ok, err := e.svc.VerifyCode(ctx, 12, code)
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
		t.Fatalf("%d concurrent requests accepted the same code", n)
	}
}
