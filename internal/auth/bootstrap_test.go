package auth

import (
	"bytes"
	"context"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type fakeStanding struct {
	mu         sync.Mutex
	eligible   map[int64]bool
	generation map[int64]int64
}

func (f *fakeStanding) BootstrapStanding(_ context.Context, _ *store.Tx, id int64) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.generation[id], f.eligible[id], nil
}

func newBootstrapEnv(t *testing.T) (*Bootstrap, *fakeStanding, *time.Time) {
	t.Helper()
	ring, err := keyring.Open([]byte("secret"), bytes.Repeat([]byte{1}, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	st := &fakeStanding{eligible: map[int64]bool{7: true, 8: true}, generation: map[int64]int64{7: 3, 8: 0}}
	b := &Bootstrap{DB: storetest.Open(t, Schema()), MAC: ring, Standing: st, Now: func() time.Time { return now }}
	return b, st, &now
}

var codeShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func TestBootstrapIssueAndRedeem(t *testing.T) {
	t.Parallel()
	b, st, now := newBootstrapEnv(t)
	ctx := t.Context()
	code, expires, err := b.Issue(ctx, 7, principal.ActionPasskeyEnroll)
	if err != nil || !codeShape.MatchString(code) || !expires.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("issue %q %v %v", code, expires, err)
	}
	if live, _ := b.Live(ctx, 7, principal.ActionPasskeyEnroll); !live {
		t.Fatal("not live")
	}
	for _, c := range []struct {
		user   int64
		action principal.Action
		code   string
	}{
		{7, principal.ActionTOTPEnroll, code},
		{8, principal.ActionPasskeyEnroll, code},
		{7, principal.ActionPasskeyEnroll, code + "x"},
		{7, principal.ActionPasskeyEnroll, "short"},
		{7, principal.ActionMFADisable, code},
	} {
		if ok, err := b.Redeem(ctx, c.user, c.action, c.code); ok || err != nil {
			t.Errorf("redeemed for %+v: %v", c, err)
		}
	}
	if ok, err := b.Redeem(ctx, 7, principal.ActionPasskeyEnroll, code); !ok || err != nil {
		t.Fatalf("redeem: %v %v", ok, err)
	}
	if ok, _ := b.Redeem(ctx, 7, principal.ActionPasskeyEnroll, code); ok {
		t.Fatal("redeemed twice")
	}
	if live, _ := b.Live(ctx, 7, principal.ActionPasskeyEnroll); live {
		t.Fatal("still live after use")
	}

	// A new code replaces the old one; the generation and the expiry bind it.
	first, _, _ := b.Issue(ctx, 7, principal.ActionTOTPEnroll)
	second, _, _ := b.Issue(ctx, 7, principal.ActionTOTPEnroll)
	if ok, _ := b.Redeem(ctx, 7, principal.ActionTOTPEnroll, first); ok {
		t.Fatal("replaced code redeemed")
	}
	st.mu.Lock()
	st.generation[7] = 4
	st.mu.Unlock()
	if ok, _ := b.Redeem(ctx, 7, principal.ActionTOTPEnroll, second); ok {
		t.Fatal("code of an older generation redeemed")
	}
	third, _, _ := b.Issue(ctx, 7, principal.ActionTOTPEnroll)
	*now = now.Add(10 * time.Minute)
	if ok, _ := b.Redeem(ctx, 7, principal.ActionTOTPEnroll, third); ok {
		t.Fatal("expired code redeemed")
	}
	fourth, _, _ := b.Issue(ctx, 7, principal.ActionTOTPEnroll)
	st.mu.Lock()
	st.eligible[7] = false
	st.mu.Unlock()
	if ok, _ := b.Redeem(ctx, 7, principal.ActionTOTPEnroll, fourth); ok {
		t.Fatal("redeemed for an account that is no longer eligible")
	}
	if _, _, err := b.Issue(ctx, 7, principal.ActionTOTPEnroll); !fault.Is(err, fault.Forbidden) {
		t.Fatalf("issue for an ineligible account: %v", err)
	}
	if _, _, err := b.Issue(ctx, 8, principal.ActionMFADisable); !fault.Is(err, fault.InvalidValue) {
		t.Fatalf("issue for another action: %v", err)
	}
}

// Concurrent redemptions of one code: exactly one succeeds.
func TestBootstrapRedeemOnce(t *testing.T) {
	t.Parallel()
	b, _, _ := newBootstrapEnv(t)
	code, _, err := b.Issue(t.Context(), 8, principal.ActionPasskeyEnroll)
	if err != nil {
		t.Fatal(err)
	}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if done, err := b.Redeem(t.Context(), 8, principal.ActionPasskeyEnroll, code); done && err == nil {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d redemptions", ok.Load())
	}
}

// Only the MAC of a code is stored.
func TestBootstrapStoresNoCode(t *testing.T) {
	t.Parallel()
	b, _, _ := newBootstrapEnv(t)
	code, _, err := b.Issue(t.Context(), 8, principal.ActionPasskeyEnroll)
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := b.DB.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT token_mac FROM auth_factor_bootstrap`).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(code)) || len(stored) != 32 {
		t.Fatalf("stored %x", stored)
	}
}
