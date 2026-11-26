package auth

import (
	"encoding/hex"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestBackoffTable(t *testing.T) {
	t.Parallel()
	want := map[int]time.Duration{0: 0, 2: 0, 3: 30 * time.Second, 4: time.Minute, 5: 2 * time.Minute, 7: 8 * time.Minute, 8: 15 * time.Minute, 40: 15 * time.Minute}
	for failures, d := range want {
		if got := Backoff(failures); got != d {
			t.Errorf("Backoff(%d) = %v, want %v", failures, got, d)
		}
	}
	if PendingShouldBeDiscarded(4) || !PendingShouldBeDiscarded(5) {
		t.Error("pending sign-in discard threshold is not 5")
	}
}

func TestThrottleClaims(t *testing.T) {
	t.Parallel()
	c := &clock{t: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
	th := &Throttle{DB: openDB(t), Now: c.Now}
	ctx := t.Context()
	for want := 1; want <= 3; want++ {
		got, err := th.Claim(ctx, 7, ScopeLogin)
		if err != nil || got != want {
			t.Fatalf("claim %d = %d, %v", want, got, err)
		}
	}
	_, err := th.Claim(ctx, 7, ScopeLogin)
	if codeOf(err) != fault.RateLimited || fault.RetryAfter(err) != 30*time.Second {
		t.Fatalf("fourth claim without waiting: %v (retry %v)", err, fault.RetryAfter(err))
	}
	if _, _, msg := fault.Status(err); msg != "Too many attempts. Try again in 30 seconds." {
		t.Errorf("message %q", msg)
	}
	// The step-up counter is independent.
	if n, err := th.Claim(ctx, 7, ScopeStepUp); err != nil || n != 1 {
		t.Fatalf("step-up claim = %d, %v", n, err)
	}
	c.Advance(30 * time.Second)
	if n, err := th.Claim(ctx, 7, ScopeLogin); err != nil || n != 4 {
		t.Fatalf("claim after the wait = %d, %v", n, err)
	}
	_, err = th.Claim(ctx, 7, ScopeLogin)
	if _, _, msg := fault.Status(err); msg != "Too many attempts. Try again in 1 minute." {
		t.Errorf("message %q", msg)
	}
	// A quiet period halves the count: 4 -> 2, so the next claim is free.
	c.Advance(QuietPeriod)
	if n, err := th.Claim(ctx, 7, ScopeLogin); err != nil || n != 3 {
		t.Fatalf("claim after a quiet period = %d, %v", n, err)
	}
	if err := th.Succeeded(ctx, 7, ScopeLogin); err != nil {
		t.Fatal(err)
	}
	if n, err := th.Claim(ctx, 7, ScopeLogin); err != nil || n != 1 {
		t.Fatalf("claim after success = %d, %v", n, err)
	}
	if err := th.ResetAll(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if n, _ := th.Claim(ctx, 7, ScopeStepUp); n != 1 {
		t.Fatalf("step-up counter not reset: %d", n)
	}
	if _, err := th.Claim(ctx, 7, Scope("other")); err == nil {
		t.Fatal("unknown scope accepted")
	}
}

// Concurrent claims cannot pass the backoff together.
func TestThrottleConcurrentClaims(t *testing.T) {
	t.Parallel()
	c := &clock{t: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
	th := &Throttle{DB: openDB(t), Now: c.Now}
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for range 20 {
		wg.Go(func() {
			if _, err := th.Claim(t.Context(), 1, ScopeLogin); err == nil {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if passed != FreeAttempts {
		t.Fatalf("%d claims passed, want %d", passed, FreeAttempts)
	}
}

// The hash matches the Python release (vector from app/recovery_service.py
// semantics), including white space and case normalisation.
func TestRecoveryHashMatchesPython(t *testing.T) {
	t.Parallel()
	const want = "5e411b6c51d381c75eac265847842eaa30513618ada21f590d471e0cbcebc1e9"
	for _, code := range []string{"ABCD-EF01-2345-6789-ABCD", " abcd-ef01-2345-6789-abcd \n", "AB CD-EF01-2345-6789-ABCD"} {
		if got := hex.EncodeToString(HashRecoveryCode(code)); got != want {
			t.Errorf("HashRecoveryCode(%q) = %s", code, got)
		}
	}
	if NormalizeRecoveryCode("abéc d") != "ABCD" {
		t.Error("non-ASCII characters are not dropped")
	}
}

func TestRecoveryCodes(t *testing.T) {
	t.Parallel()
	rc := &Recovery{DB: openDB(t), iterations: 1}
	ctx := t.Context()
	codes, err := rc.Generate(ctx, 3)
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("Generate = %d codes, %v", len(codes), err)
	}
	format := regexp.MustCompile(`^[0-9A-F]{4}(-[0-9A-F]{4}){4}$`)
	seen := map[string]bool{}
	for _, c := range codes {
		if !format.MatchString(c) || seen[c] {
			t.Fatalf("code %q is malformed or repeated", c)
		}
		seen[c] = true
	}
	if ok, _ := rc.Consume(ctx, 4, codes[0]); ok {
		t.Fatal("another user's code was accepted")
	}
	if ok, err := rc.Consume(ctx, 3, "  "+codes[0]+" "); !ok || err != nil {
		t.Fatalf("own code rejected: %v", err)
	}
	if ok, _ := rc.Consume(ctx, 3, codes[0]); ok {
		t.Fatal("a used code was accepted again")
	}
	if ok, _ := rc.Consume(ctx, 3, "0000-0000-0000-0000-0000"); ok {
		t.Fatal("a wrong code was accepted")
	}
	if ok, _ := rc.Consume(ctx, 3, ""); ok {
		t.Fatal("an empty code was accepted")
	}
	// Rotation invalidates the old codes.
	fresh, err := rc.Generate(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := rc.Consume(ctx, 3, codes[1]); ok {
		t.Fatal("a code from before the rotation was accepted")
	}
	if ok, _ := rc.Consume(ctx, 3, fresh[9]); !ok {
		t.Fatal("a new code was rejected")
	}
}

// A migrated hash (copied byte for byte) works once.
func TestRecoveryImport(t *testing.T) {
	t.Parallel()
	rc := &Recovery{DB: openDB(t), iterations: 1}
	ctx := t.Context()
	h, _ := hex.DecodeString("5e411b6c51d381c75eac265847842eaa30513618ada21f590d471e0cbcebc1e9")
	err := rc.DB.Write(ctx, func(tx *store.Tx) error { return rc.ImportTx(ctx, tx, 9, [][]byte{h}) })
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.DB.Write(ctx, func(tx *store.Tx) error { return rc.ImportTx(ctx, tx, 9, [][]byte{h[:31]}) }); err == nil {
		t.Fatal("a short hash was imported")
	}
	if ok, _ := rc.Consume(ctx, 9, "abcd-ef01-2345-6789-abcd"); !ok {
		t.Fatal("migrated code rejected")
	}
	if ok, _ := rc.Consume(ctx, 9, "abcd-ef01-2345-6789-abcd"); ok {
		t.Fatal("migrated code accepted twice")
	}
}

func newMFA(t *testing.T) (*MFA, *fakeAccounts, *fakeTOTP, *fakeSessions) {
	t.Helper()
	accounts := &fakeAccounts{mfa: map[int64]bool{}}
	totp := &fakeTOTP{count: map[int64]int{}}
	sessions := &fakeSessions{}
	m := &MFA{DB: openDB(t), Accounts: accounts, Gates: fakeGates{FeatureTOTP: true, FeatureRecovery: true, FeaturePasskey: true}, TOTP: totp, Sessions: sessions}
	return m, accounts, totp, sessions
}

func TestMFADisable(t *testing.T) {
	t.Parallel()
	m, accounts, totp, sessions := newMFA(t)
	ctx := t.Context()
	p := principaltest.User(5)
	if err := m.Disable(ctx, p); codeOf(err) != fault.Conflict {
		t.Fatalf("disable without MFA = %v, want conflict", err)
	}
	accounts.mfa[5], totp.count[5] = true, 2
	th := &Throttle{DB: m.DB}
	if _, err := th.Claim(ctx, 5, ScopeLogin); err != nil {
		t.Fatal(err)
	}
	if err := m.Disable(ctx, p); err != nil {
		t.Fatal(err)
	}
	if accounts.mfa[5] || totp.count[5] != 0 || len(sessions.ended) != 0 {
		t.Fatalf("state after disable: mfa %v, totp %d, sessions %v", accounts.mfa[5], totp.count[5], sessions.ended)
	}
	if n, _ := th.Claim(ctx, 5, ScopeLogin); n != 1 {
		t.Fatal("disable did not clear the backoff")
	}
	// In a recovery session the restriction ends with BASIC assurance.
	rp := principaltest.User(6)
	rp.Recovery = true
	accounts.mfa[6] = true
	if err := m.Disable(ctx, rp); err != nil {
		t.Fatal(err)
	}
	if len(sessions.ended) != 1 || sessions.ended[0] != "session-6||basic" {
		t.Fatalf("recovery end = %v", sessions.ended)
	}
}

func TestSecurityState(t *testing.T) {
	t.Parallel()
	m, accounts, totp, _ := newMFA(t)
	totp.count[1] = 2
	s, err := m.State(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if s.MFAEnabled || s.TOTP != 2 || s.Total != 2 || s.CanEnableMFA || s.CanDisableMFA {
		t.Fatalf("state %+v", s)
	}
	accounts.mfa[1] = true
	m.Gates = fakeGates{FeatureTOTP: false}
	if s, _ = m.State(t.Context(), 1); s.TOTP != 0 || !s.CanDisableMFA {
		t.Fatalf("state with TOTP off %+v", s)
	}
}
