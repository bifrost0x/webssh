package ldap

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestAuthenticateLinkedAccount(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	f.now = f.now.Add(time.Hour)
	id, err := f.svc.Authenticate(t.Context(), "  alice\u00a0", "pw-a")
	if err != nil || id != 7 {
		t.Fatalf("sign-in: %d %v", id, err)
	}
	row, _, _ := f.svc.IdentityOf(t.Context(), 7)
	if !row.LastVerifiedAt.Equal(f.now) || row.DirectoryUsername != "alice" {
		t.Fatalf("identity not updated: %+v", row)
	}
	if _, checked := f.revalidation(t, 7); !checked.Equal(f.now) {
		t.Fatalf("check not recorded: %v", checked)
	}
}

func TestAuthenticateRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		setup    func(f *fixture)
		name, pw string
		code     fault.Code
		binds    int
	}{
		"wrong password":      {name: "alice", pw: "nope", code: fault.AuthFailed, binds: 1},
		"empty password":      {name: "alice", pw: "", code: fault.AuthFailed, binds: 1},
		"unknown name":        {name: "mallory", pw: "x", code: fault.AuthFailed},
		"unlinked, no auto":   {setup: func(f *fixture) { f.dir.add("bob", "uuid-b", "pw-b") }, name: "bob", pw: "pw-b", code: fault.AuthFailed},
		"locked account":      {setup: func(f *fixture) { f.accounts.accounts[7].IsLocked = true }, name: "alice", pw: "pw-a", code: fault.AuthFailed},
		"admin account":       {setup: func(f *fixture) { f.accounts.accounts[7].IsAdmin = true }, name: "alice", pw: "pw-a", code: fault.AuthFailed},
		"directory down":      {setup: func(f *fixture) { f.dir.down = true }, name: "alice", pw: "pw-a", code: fault.Unavailable},
		"feature inactive":    {setup: func(f *fixture) { f.svc.Gates = gates{off: true} }, name: "alice", pw: "pw-a", code: fault.Unavailable},
		"LDAP off":            {setup: func(f *fixture) { f.svc.Enabled = false }, name: "alice", pw: "pw-a", code: fault.Unavailable},
		"other provider name": {setup: func(f *fixture) { f.svc.Provider = "other" }, name: "alice", pw: "pw-a", code: fault.AuthFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
			if tc.setup != nil {
				tc.setup(f)
			}
			_, err := f.svc.Authenticate(t.Context(), tc.name, tc.pw)
			if fault.CodeOf(err) != tc.code {
				t.Fatalf("got %v, want %s", err, tc.code)
			}
			if f.dir.binds != tc.binds {
				t.Fatalf("%d binds, want %d", f.dir.binds, tc.binds)
			}
		})
	}
}

func TestAutoProvision(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.svc.AutoProvision = true
	f.dir.add("carol", "uuid-c", "pw-c")
	id, err := f.svc.Authenticate(t.Context(), "carol", "pw-c")
	if err != nil {
		t.Fatal(err)
	}
	acc := f.accounts.get(id)
	if acc.Username != "carol" || acc.Managed != "ldap" || acc.IsAdmin {
		t.Fatalf("account %+v", acc)
	}
	again, err := f.svc.Authenticate(t.Context(), "carol", "pw-c")
	if err != nil || again != id {
		t.Fatalf("second sign-in: %d %v", again, err)
	}
	// A wrong password never provisions.
	f.dir.add("dave", "uuid-d", "pw-d")
	if _, err := f.svc.Authenticate(t.Context(), "dave", "wrong"); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	if len(f.accounts.accounts) != 2 {
		t.Fatalf("accounts %d", len(f.accounts.accounts))
	}
}

func TestAutoProvisionRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		setup     func(f *fixture)
		presented string
	}{
		"name taken after case folding": {setup: func(f *fixture) { f.accounts.add(Account{ID: 5, Username: "Erin"}) }, presented: "erin"},
		"no break-glass administrator":  {setup: func(f *fixture) { f.accounts.accounts[1].IsLocked = true }, presented: "erin"},
		"control character":             {presented: "erin\u200b"},
		"too long":                      {presented: strings.Repeat("e", 81)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.svc.AutoProvision = true
			f.dir.add(pyStrip(tc.presented), "uuid-e", "pw-e")
			if tc.setup != nil {
				tc.setup(f)
			}
			before := len(f.accounts.accounts)
			if _, err := f.svc.Authenticate(t.Context(), tc.presented, "pw-e"); !fault.Is(err, fault.AuthFailed) {
				t.Fatalf("got %v", err)
			}
			if len(f.accounts.accounts) != before {
				t.Fatal("an account was created")
			}
		})
	}
}

func TestHasOtherCategory(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"alice": false, "Jürgen Ölmann": false, "日本": false, "a\tb": true, "a\u200bb": true, "\ue000": true,
		"\u0378": true, "a\xffb": true, "\U0001f600": false,
	} {
		if got := hasOtherCategory(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

// TestRequiredCheckClearedBySignIn is the functional verification of E37:
// a fenced account is signed out by the gate, and its next LDAP sign-in
// runs the directory check, ends the old sessions and clears the fence.
func TestRequiredCheckClearedBySignIn(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	f.require(t, 7)
	p := principaltest.User(7)
	gen := f.accounts.get(7).Generation
	if err := f.svc.Gate(t.Context(), p); !fault.Is(err, fault.AuthenticationNeeded) {
		t.Fatalf("gate: %v", err)
	}
	if f.accounts.get(7).Generation != gen+1 || f.sessions.count(7) != 1 {
		t.Fatal("gate did not invalidate")
	}
	lookups := f.dir.lookups
	if _, err := f.svc.Authenticate(t.Context(), "alice", "pw-a"); err != nil {
		t.Fatal(err)
	}
	if f.dir.lookups != lookups+1 || f.sessions.count(7) != 2 {
		t.Fatalf("sign-in did not check the directory or end old sessions (%d lookups, %d revocations)", f.dir.lookups-lookups, f.sessions.count(7))
	}
	if required, _ := f.revalidation(t, 7); required {
		t.Fatal("still required")
	}
	if err := f.svc.Gate(t.Context(), p); err != nil {
		t.Fatalf("gate after sign-in: %v", err)
	}
}

func TestGate(t *testing.T) {
	t.Parallel()
	p := principaltest.User(7)
	t.Run("account without identity", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		f.accounts.add(Account{ID: 7, Username: "local"})
		if err := f.svc.Gate(t.Context(), p); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("fresh check", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
		f.now = f.now.Add(4 * time.Minute)
		if err := f.svc.Gate(t.Context(), p); err != nil || f.dir.lookups != 0 {
			t.Fatalf("%v, %d lookups", err, f.dir.lookups)
		}
	})
	t.Run("stale check passes", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
		f.now = f.now.Add(6 * time.Minute)
		if err := f.svc.Gate(t.Context(), p); err != nil || f.dir.lookups != 1 {
			t.Fatalf("%v, %d lookups", err, f.dir.lookups)
		}
		if _, checked := f.revalidation(t, 7); !checked.Equal(f.now) {
			t.Fatal("check not recorded")
		}
	})
	for name, setup := range map[string]func(f *fixture){
		"LDAP off":           func(f *fixture) { f.svc.Enabled = false },
		"directory down":     func(f *fixture) { f.now = f.now.Add(time.Hour); f.dir.down = true },
		"entry gone":         func(f *fixture) { f.now = f.now.Add(time.Hour); delete(f.dir.entries, "alice") },
		"subject changed":    func(f *fixture) { f.now = f.now.Add(time.Hour); f.dir.add("alice", "uuid-other", "pw-a") },
		"account locked":     func(f *fixture) { f.now = f.now.Add(time.Hour); f.accounts.accounts[7].IsLocked = true },
		"provider id change": func(f *fixture) { f.now = f.now.Add(time.Hour); f.svc.Provider = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
			setup(f)
			gen := f.accounts.get(7).Generation
			if err := f.svc.Gate(t.Context(), p); !fault.Is(err, fault.AuthenticationNeeded) {
				t.Fatalf("gate: %v", err)
			}
			if f.accounts.get(7).Generation != gen+1 || f.sessions.revoked[7][0] != principal.ReasonDirectoryRefused {
				t.Fatal("access not ended")
			}
		})
	}
}

func TestGateRefusesWhileAnotherRequestChecks(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	f.now = f.now.Add(time.Hour)
	f.dir.block = make(chan struct{})
	p := principaltest.User(7)
	var wg sync.WaitGroup
	var first error
	wg.Go(func() { first = f.svc.Gate(t.Context(), p) })
	for {
		f.dir.mu.Lock()
		started := f.dir.lookups > 0
		f.dir.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	err := f.svc.Gate(t.Context(), p)
	if !fault.Is(err, fault.LDAPValidationInProgress) || fault.RetryAfter(err) != time.Second {
		t.Fatalf("second request: %v", err)
	}
	close(f.dir.block)
	wg.Wait()
	if first != nil {
		t.Fatalf("first request: %v", first)
	}
}

func TestSweep(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	f.linkUser(t, 8, "bob", "uuid-b", "pw-b")
	f.linkUser(t, 9, "carol", "uuid-c", "pw-c")
	f.require(t, 9)
	f.now = f.now.Add(time.Hour)
	delete(f.dir.entries, "bob")
	n, err := f.svc.Sweep(t.Context())
	if err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if f.sessions.count(7) != 0 || f.sessions.count(8) != 1 || f.sessions.count(9) != 1 {
		t.Fatalf("revocations %v", f.sessions.revoked)
	}
	if f.accounts.get(9).Generation != 0 {
		t.Fatal("a required account is only signed out, its generation stays")
	}
	// A second sweep in the same instant skips the accounts it checked.
	lookups := f.dir.lookups
	if _, err := f.svc.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.dir.lookups != lookups+1 { // only bob, whose check failed, is looked up again
		t.Fatalf("lookups %d", f.dir.lookups-lookups)
	}
}

func TestRevalidateFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	f.dir.down = true
	if err := f.svc.Revalidate(t.Context(), 7); err == nil {
		t.Fatal("an unreachable directory must fail")
	}
	if f.sessions.count(7) != 1 {
		t.Fatal("sessions not ended")
	}
	f.dir.down = false
	if err := f.svc.Revalidate(t.Context(), 7); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyStepUp(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	if ok, err := f.svc.StepUpLinked(t.Context(), 7); !ok || err != nil {
		t.Fatalf("linked: %v %v", ok, err)
	}
	if ok, _ := f.svc.StepUpLinked(t.Context(), 1); ok {
		t.Fatal("a local account has no LDAP step-up")
	}
	f.now = f.now.Add(time.Minute)
	if ok, err := f.svc.VerifyStepUp(t.Context(), 7, "pw-a"); !ok || err != nil {
		t.Fatalf("right password: %v %v", ok, err)
	}
	if row, _, _ := f.svc.IdentityOf(t.Context(), 7); !row.LastVerifiedAt.Equal(f.now) {
		t.Fatal("verification time not recorded")
	}
	for _, pw := range []string{"wrong", "", strings.Repeat("x", 4097)} {
		if ok, err := f.svc.VerifyStepUp(t.Context(), 7, pw); ok || err != nil {
			t.Fatalf("%q: %v %v", pw, ok, err)
		}
	}
	f.dir.add("alice", "uuid-new", "pw-a")
	if ok, err := f.svc.VerifyStepUp(t.Context(), 7, "pw-a"); ok || err != nil {
		t.Fatalf("changed binding: %v %v", ok, err)
	}
	f.dir.down = true
	if _, err := f.svc.VerifyStepUp(t.Context(), 7, "pw-a"); !fault.Is(err, fault.Unavailable) {
		t.Fatalf("down: %v", err)
	}
	f.svc.Gates = gates{off: true}
	if ok, _ := f.svc.StepUpLinked(t.Context(), 7); ok {
		t.Fatal("offered while LDAP is inactive")
	}
}

func TestIdentityLinks(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.linkUser(t, 7, "alice", "uuid-a", "pw-a")
	ctx := t.Context()
	id := identityFor("corp", "uuid-a")
	if u, err := f.svc.Account(ctx, id); err != nil || u != 7 {
		t.Fatalf("account: %d %v", u, err)
	}
	if _, err := f.svc.Account(ctx, identityFor("other", "uuid-a")); !fault.Is(err, fault.NotFound) {
		t.Fatalf("other provider: %v", err)
	}
	f.accounts.add(Account{ID: 8, Username: "bob"})
	err := f.svc.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := f.svc.LinkTx(ctx, tx, 8, id)
		return err
	})
	if !fault.Is(err, fault.Conflict) {
		t.Fatalf("second link of a binding: %v", err)
	}
	list, err := f.svc.List(ctx, 7)
	if err != nil || len(list) != 1 || list[0].Subject != "uuid-a" || list[0].Issuer != "corp" {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := f.svc.Unlink(ctx, 7, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Unlink(ctx, 7, list[0].ID); !fault.Is(err, fault.NotFound) {
		t.Fatalf("second unlink: %v", err)
	}
	if _, err := f.svc.Provision(ctx, id); !fault.Is(err, fault.Forbidden) {
		t.Fatalf("provision without LDAP_AUTO_PROVISION: %v", err)
	}
}
