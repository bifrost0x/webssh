package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// fakeDirectory is a directory with users name -> entry and passwords
// DN -> password. down makes every call ErrUnavailable.
type fakeDirectory struct {
	mu        sync.Mutex
	entries   map[string]Entry
	passwords map[string]string
	down      bool
	lookups   int
	binds     int
	block     chan struct{} // when set, Lookup waits for it
	ready     error
}

func newDirectory() *fakeDirectory {
	return &fakeDirectory{entries: map[string]Entry{}, passwords: map[string]string{}}
}

func (d *fakeDirectory) add(name, subject, password string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	dn := "uid=" + name + ",dc=example"
	d.entries[name] = Entry{Subject: subject, DN: dn}
	d.passwords[dn] = password
}

func (d *fakeDirectory) Lookup(_ context.Context, username string) (Entry, error) {
	d.mu.Lock()
	block := d.block
	d.lookups++
	d.mu.Unlock()
	if block != nil {
		<-block
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.down {
		return Entry{}, fmt.Errorf("%w: down", ErrUnavailable)
	}
	e, ok := d.entries[pyStrip(username)]
	if !ok {
		return Entry{}, fmt.Errorf("%w: no entry", ErrRejected)
	}
	return e, nil
}

func (d *fakeDirectory) VerifyPassword(_ context.Context, dn, password string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.binds++
	if d.down {
		return false, fmt.Errorf("%w: down", ErrUnavailable)
	}
	return password != "" && d.passwords[dn] == password, nil
}

func (d *fakeDirectory) Probe(context.Context) error {
	if d.down {
		return ErrUnavailable
	}
	return nil
}

func (d *fakeDirectory) Ready() error      { return d.ready }
func (d *fakeDirectory) Transport() string { return "ldap+StartTLS" }

// fakeAccounts keeps accounts in memory; the transaction is not used.
type fakeAccounts struct {
	mu       sync.Mutex
	accounts map[int64]*Account
	next     int64
	released map[int64]string
}

func newAccounts() *fakeAccounts {
	return &fakeAccounts{accounts: map[int64]*Account{}, next: 100, released: map[int64]string{}}
}

func (a *fakeAccounts) add(acc Account) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accounts[acc.ID] = &acc
}

func (a *fakeAccounts) get(id int64) Account {
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a.accounts[id]
}

func (a *fakeAccounts) GetTx(_ context.Context, _ *store.Tx, id int64) (Account, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, ok := a.accounts[id]
	if !ok {
		return Account{}, fault.New(fault.NotFound, "")
	}
	return *acc, nil
}

func (a *fakeAccounts) ProvisionTx(_ context.Context, _ *store.Tx, username, manager string) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, acc := range a.accounts {
		if strings.EqualFold(acc.Username, username) {
			return 0, fault.New(fault.Conflict, "")
		}
	}
	a.next++
	a.accounts[a.next] = &Account{ID: a.next, Username: username, Managed: manager}
	return a.next, nil
}

func (a *fakeAccounts) ReleaseTx(_ context.Context, _ *store.Tx, id int64, hash string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accounts[id].Managed = ""
	a.accounts[id].Generation++
	a.released[id] = hash
	return nil
}

func (a *fakeAccounts) AdoptTx(_ context.Context, _ *store.Tx, id int64, manager string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accounts[id].Managed = manager
	a.accounts[id].Generation++
	return nil
}

func (a *fakeAccounts) RaiseGenerationTx(_ context.Context, _ *store.Tx, id int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, ok := a.accounts[id]
	if !ok {
		return fault.New(fault.NotFound, "")
	}
	acc.Generation++
	return nil
}

func (a *fakeAccounts) BreakGlassAdminTx(context.Context, *store.Tx) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, acc := range a.accounts {
		if acc.IsAdmin && !acc.IsLocked && acc.Managed != "ldap" {
			return true, nil
		}
	}
	return false, nil
}

type fakeSessions struct {
	mu      sync.Mutex
	revoked map[int64][]principal.Reason
}

func (s *fakeSessions) RevokeUser(_ context.Context, id int64, reason principal.Reason, _ string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked == nil {
		s.revoked = map[int64][]principal.Reason{}
	}
	s.revoked[id] = append(s.revoked[id], reason)
	return 1, nil
}

func (s *fakeSessions) count(id int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.revoked[id])
}

type fakePasswords struct{}

func (fakePasswords) ValidateNew(p string) string {
	if len(p) < 8 {
		return "Password must be at least 8 characters"
	}
	return ""
}

func (fakePasswords) Hash(_ context.Context, p string) (string, error) { return "hash:" + p, nil }

type fakeOIDC struct{ removed []int64 }

func (o *fakeOIDC) RemoveAllTx(_ context.Context, _ *store.Tx, id int64) error {
	o.removed = append(o.removed, id)
	return nil
}

type gates struct{ off bool }

func (g gates) Active(context.Context, string) (bool, error) { return !g.off, nil }

type fixture struct {
	svc      *Service
	dir      *fakeDirectory
	accounts *fakeAccounts
	sessions *fakeSessions
	stepup   *principaltest.StepUp
	oidc     *fakeOIDC
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: newDirectory(), accounts: newAccounts(), sessions: &fakeSessions{}, stepup: &principaltest.StepUp{},
		oidc: &fakeOIDC{}, now: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)}
	f.svc = &Service{DB: storetest.Open(t, Schema()), Directory: f.dir, Accounts: f.accounts, Sessions: f.sessions,
		StepUp: f.stepup, Passwords: fakePasswords{}, OIDC: f.oidc, Gates: gates{}, Enabled: true, Provider: "corp",
		Revalidation: 5 * time.Minute, Now: func() time.Time { return f.now }, Logger: slog.New(slog.DiscardHandler),
		Admins: func(name string) bool { return name == "root" }}
	f.accounts.add(Account{ID: 1, Username: "root", IsAdmin: true})
	return f
}

// linkUser creates account id with an identity of name/subject in the
// directory and the store, checked at the fixture's clock.
func (f *fixture) linkUser(t *testing.T, id int64, name, subject, password string) {
	t.Helper()
	f.dir.add(name, subject, password)
	f.accounts.add(Account{ID: id, Username: name, Managed: "ldap"})
	err := f.svc.DB.Write(t.Context(), func(tx *store.Tx) error {
		if _, err := insertIdentityTx(t.Context(), tx, Identity{UserID: id, Provider: "corp", Subject: subject,
			DirectoryUsername: name, DistinguishedName: "uid=" + name + ",dc=example", CreatedAt: f.now}); err != nil {
			return err
		}
		return checkedTx(t.Context(), tx, id, f.now)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) revalidation(t *testing.T, id int64) (bool, time.Time) {
	t.Helper()
	var required bool
	var checked time.Time
	err := f.svc.DB.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		required, checked, err = RevalidationTx(t.Context(), tx, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return required, checked
}

func (f *fixture) require(t *testing.T, id int64) {
	t.Helper()
	if err := f.svc.DB.Write(t.Context(), func(tx *store.Tx) error { return RequireRevalidationTx(t.Context(), tx, id) }); err != nil {
		t.Fatal(err)
	}
}
