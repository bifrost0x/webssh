package totp

import (
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

// Vector from app/totp_service.py:_provisioning_uri with the same input.
func TestProvisioningURIMatchesPython(t *testing.T) {
	t.Parallel()
	got := ProvisioningURI("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "üser x/y~_.-:@")
	want := "otpauth://totp/WebSSH:%C3%BCser%20x/y~_.-%3A%40?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=WebSSH"
	if got != want {
		t.Fatalf("URI\n got %s\nwant %s", got, want)
	}
}

func TestAcceptedStepWindow(t *testing.T) {
	t.Parallel()
	key := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	// RFC 6238 appendix B: 1111111109 -> 07081804 (8 digits); the six-digit
	// code is its last six digits.
	if step, ok := acceptedStep(key, " 081804 ", now); !ok || step != 1111111109/30 {
		t.Fatalf("code of the current step: %d %v", step, ok)
	}
	for _, bad := range []string{"", "08180", "0818045", "08180a", "０８１８０４", "081 804"} {
		if _, ok := acceptedStep(key, bad, now); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, ok := acceptedStep(key, "081804", now.Add(95*time.Second)); ok {
		t.Error("accepted a code three steps old")
	}
}

func TestNormalizeLabel(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"": DefaultLabel, " Phone ": "Phone", strings.Repeat("é", 80): strings.Repeat("é", 80)} {
		if got, ok := NormalizeLabel(in, true); !ok || got != want {
			t.Errorf("NormalizeLabel(%q) = %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"   ", strings.Repeat("x", 81)} {
		if _, ok := NormalizeLabel(in, true); ok {
			t.Errorf("NormalizeLabel(%q) accepted", in)
		}
	}
	if got, ok := NormalizeLabel("", false); !ok || got != DefaultLabel {
		t.Error("absent label is not the default")
	}
}

func TestEnrolmentAndActivation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(1)
	en, err := e.svc.Begin(ctx, p, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if len(en.Secret) != 32 || !strings.HasPrefix(en.ProvisioningURI, "otpauth://totp/WebSSH:user1?secret="+en.Secret) || !strings.Contains(en.QRSVG, `id="qr-path"`) {
		t.Fatalf("enrolment %+v", en)
	}
	// Another browser session of the same user cannot finish it.
	other := p
	other.SessionID = "other"
	if _, err := e.svc.Activate(ctx, other, en.Token, e.codeAt(t, en.Secret, 0)); !fault.Is(err, fault.InvalidRequest) {
		t.Fatalf("activation from another session: %v", err)
	}
	if _, err := e.svc.Activate(ctx, p, en.Token, "000000"); !fault.Is(err, fault.InvalidRequest) {
		t.Fatalf("wrong first code: %v", err)
	}
	a, err := e.svc.Activate(ctx, p, en.Token, e.codeAt(t, en.Secret, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.RecoveryCodes) != 10 || !e.accounts.mfa[1] {
		t.Fatalf("first activation: %d codes, mfa %v", len(a.RecoveryCodes), e.accounts.mfa[1])
	}
	if _, err := e.svc.Activate(ctx, p, en.Token, e.codeAt(t, en.Secret, 0)); err == nil {
		t.Fatal("an enrolment was activated twice")
	}
	// The first code is the last accepted step: it cannot sign in again.
	if ok, _ := e.svc.VerifyCode(ctx, 1, e.codeAt(t, en.Secret, 0)); ok {
		t.Fatal("the activation code was accepted again")
	}
	// A second authenticator keeps MFA and rotates no codes.
	_, b := e.enrol(t, p)
	if len(b.RecoveryCodes) != 0 {
		t.Fatal("second activation rotated the recovery codes")
	}
	list, err := e.svc.List(ctx, 1)
	if err != nil || len(list) != 2 || list[0].Label != "Phone" || list[1].Label != DefaultLabel {
		t.Fatalf("list %+v %v", list, err)
	}
}

func TestEnrolmentExpiresAndLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(2)
	en, err := e.svc.Begin(ctx, p, DefaultLabel)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(EnrollmentTTL)
	if _, err := e.svc.Activate(ctx, p, en.Token, e.codeAt(t, en.Secret, 0)); err == nil {
		t.Fatal("expired enrolment activated")
	}
	for range MaxAuthenticators {
		e.enrol(t, p)
		e.clock.Advance(31 * time.Second)
	}
	en, err = e.svc.Begin(ctx, p, DefaultLabel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Activate(ctx, p, en.Token, e.codeAt(t, en.Secret, 0)); err == nil {
		t.Fatal("a sixth authenticator was activated")
	}
	var pending int
	for range MaxEnrollments + 3 {
		if _, err := e.svc.Begin(ctx, p, DefaultLabel); err != nil {
			t.Fatal(err)
		}
	}
	_ = e.svc.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM totp_enrollments WHERE user_id = 2`).Scan(&pending)
	})
	if pending != MaxEnrollments {
		t.Fatalf("%d pending enrolments, want %d", pending, MaxEnrollments)
	}
}

func TestVerifyReplayAndSkew(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(3)
	secret, _ := e.enrol(t, p)
	e.clock.Advance(2 * time.Minute)
	if ok, _ := e.svc.VerifyCode(ctx, 3, e.codeAt(t, secret, -2)); ok {
		t.Fatal("code two steps old accepted")
	}
	if ok, _ := e.svc.VerifyCode(ctx, 3, e.codeAt(t, secret, 1)); !ok {
		t.Fatal("code of the next step rejected")
	}
	// Steps at or below the last accepted one are replays.
	for _, off := range []int64{1, 0, -1} {
		if ok, _ := e.svc.VerifyCode(ctx, 3, e.codeAt(t, secret, off)); ok {
			t.Fatalf("replay at offset %d accepted", off)
		}
	}
	if ok, _ := e.svc.VerifyCode(ctx, 4, e.codeAt(t, secret, 1)); ok {
		t.Fatal("another user's code accepted")
	}
}

// A sealed secret moved to another user or row does not open.
func TestSecretBoundToRowAndUser(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	secret, a := e.enrol(t, principaltest.User(5))
	err := e.svc.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE totp_authenticators SET user_id = 6 WHERE id = ?`, a.AuthenticatorID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	if ok, _ := e.svc.VerifyCode(ctx, 6, e.codeAt(t, secret, 0)); ok {
		t.Fatal("a moved secret verified")
	}
	other, _ := keyring.Open([]byte("another-secret"), make([]byte, keyring.MaterialSize))
	e.svc.Ring = other
	if ok, _ := e.svc.VerifyCode(ctx, 5, e.codeAt(t, secret, 0)); ok {
		t.Fatal("a secret opened under another key")
	}
}

func TestCheckCodeThrottle(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	secret, _ := e.enrol(t, principaltest.User(7))
	for i := 1; i <= 3; i++ {
		err := e.svc.CheckCode(ctx, 7, "000000", "step_up")
		if !fault.Is(err, fault.AuthFailed) || Failures(err) != i {
			t.Fatalf("attempt %d: %v (failures %d)", i, err, Failures(err))
		}
	}
	e.clock.Advance(time.Minute)
	good := e.codeAt(t, secret, 0)
	if err := e.svc.CheckCode(ctx, 7, "000000", "step_up"); Failures(err) != 4 {
		t.Fatalf("fourth attempt: %v", err)
	}
	if err := e.svc.CheckCode(ctx, 7, good, "step_up"); !fault.Is(err, fault.RateLimited) {
		t.Fatalf("attempt during the backoff: %v", err)
	}
	if err := e.svc.CheckCode(ctx, 7, good, "login"); err != nil {
		t.Fatalf("sign-in counter is affected by step-up failures: %v", err)
	}
}

func TestDeleteKeepsLastFactor(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(8)
	_, a := e.enrol(t, p)
	if _, err := e.svc.Delete(ctx, principaltest.User(9), a.AuthenticatorID); !fault.Is(err, fault.NotFound) {
		t.Fatalf("foreign delete: %v", err)
	}
	if _, err := e.svc.Delete(ctx, p, a.AuthenticatorID); !fault.Is(err, fault.LastFactorRequired) {
		t.Fatalf("deleting the last factor: %v", err)
	}
	e.passkeys.n = 1
	if on, err := e.svc.Delete(ctx, p, a.AuthenticatorID); err != nil || !on {
		t.Fatalf("delete with a passkey left: %v %v", on, err)
	}
}
