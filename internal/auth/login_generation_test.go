package auth

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// slowPassword is the local provider with the hash verification taking
// time (a busy hash slot queue): the row is read and checked, then the
// answer arrives after the password change committed.
type slowPassword struct {
	*fakePasswords
	verified chan struct{}
	resume   chan struct{}
}

func (s slowPassword) Authenticate(ctx context.Context, name, pw string) (int64, error) {
	id, err := s.fakePasswords.Authenticate(ctx, name, pw) // old password checked against the old row
	if err == nil {
		close(s.verified)
		<-s.resume
	}
	return id, err
}

// TestLoginRefusedAfterConcurrentPasswordChange: a sign-in whose password
// was checked against the hash a concurrent password change replaced must
// not end in a session.
func TestLoginRefusedAfterConcurrentPasswordChange(t *testing.T) {
	e := newEnv(t, false)
	acc := e.createUser(t, "victim", "oldpassword")
	sp := slowPassword{fakePasswords: e.pw, verified: make(chan struct{}), resume: make(chan struct{})}
	e.flow.Password = sp

	attacker := e.browser()
	done := make(chan struct{})
	go func() {
		defer close(done)
		attacker.do("POST", "/login", creds("victim", "oldpassword"))
	}()
	<-sp.verified

	// The owner (or reset-password) changes the password now: new hash,
	// generation raised, every session ended.
	ctx := t.Context()
	err := e.flow.DB.Write(ctx, func(tx *store.Tx) error {
		if err := e.pw.StoreTx(ctx, tx, acc.ID, "h:newpassword"); err != nil {
			return err
		}
		if _, err := e.flow.Accounts.PasswordChangedTx(ctx, tx, acc.ID, "h:newpassword"); err != nil {
			return err
		}
		_, err := e.flow.Sessions.RevokeAccountTx(ctx, tx, acc.ID, principal.ReasonPasswordChanged)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	close(sp.resume)
	<-done

	if p, err := e.flow.Sessions.Authenticate(ctx, attacker.cookies["session"]); err == nil {
		t.Fatalf("sign-in with the old password holds a session after the password change (user %d)", p.UserID)
	}
}
