package stepup

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// The step-up service with the real TOTP factor refuses a code
// that already completed the sign-in, and a step-up code is single-use.
func TestStepUpTOTPReplay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	db := storetest.Open(t, auth.Schema(), totp.Schema())
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	ts := &totp.Service{DB: db, Ring: e.svc.Ring, Now: e.clock.Now, Throttle: &auth.Throttle{DB: db, Now: e.clock.Now}}
	if err := db.Write(ctx, func(tx *store.Tx) error {
		return ts.ImportTx(ctx, tx, totp.Imported{ID: 1, UserID: 21, Label: "a", Base32: secret, Active: true, CreatedAt: e.clock.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	e.svc.TOTP = ts
	e.accounts.mfa[21] = true
	p := principaltest.User(21)
	key, _ := otp.DecodeSecret(secret)
	code, _ := otp.TOTP(key, otp.Step(e.clock.Now(), otp.DefaultPeriod))

	// The code completes a sign-in first.
	if err := ts.CheckCode(ctx, 21, code, auth.ScopeLogin); err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	c, err := e.svc.Begin(ctx, p, principal.ActionKeyDelete, "k", ChannelAccount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodTOTP, Secret: code}); !Rejected(err) {
		t.Fatalf("sign-in code replayed as step-up proof: %v", err)
	}
	// A fresh code works once; its replay on a second intent is refused.
	e.clock.Advance(time.Minute)
	code, _ = otp.TOTP(key, otp.Step(e.clock.Now(), otp.DefaultPeriod))
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodTOTP, Secret: code}); err != nil {
		t.Fatalf("fresh code: %v", err)
	}
	c2, err := e.svc.Begin(ctx, p, principal.ActionKeyDelete, "k2", ChannelAccount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Prove(ctx, p, c2.Intent, Proof{Method: MethodTOTP, Secret: code}); !Rejected(err) {
		t.Fatalf("step-up code replayed: %v", err)
	}
}
