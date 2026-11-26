// Package authtest holds test doubles of the external identity contracts
// of internal/auth: a redirect provider, the identity links of one
// provider and a revalidator. Only test files import it.
package authtest

import (
	"context"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Provider is an auth.ExternalProvider that signs in whoever the test put
// into Codes. Begin returns a URL below Authorize with the flight's state
// and PKCE challenge; Complete applies Flight.Accept and then the code.
type Provider struct {
	ProviderName auth.ProviderName
	Authorize    string // default "https://idp.example/authorize"
	Now          func() time.Time

	mu    sync.Mutex
	codes map[string]auth.Identity
	used  map[string]bool
}

var _ auth.ExternalProvider = (*Provider)(nil)

// Name implements auth.ExternalProvider.
func (p *Provider) Name() auth.ProviderName { return p.ProviderName }

// Issue makes code redeemable once for id.
func (p *Provider) Issue(code string, id auth.Identity) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.codes == nil {
		p.codes, p.used = map[string]auth.Identity{}, map[string]bool{}
	}
	id.Provider = p.ProviderName
	p.codes[code] = id
}

// Begin implements auth.ExternalProvider.
func (p *Provider) Begin(_ context.Context, f auth.Flight) (string, error) {
	if f.Provider != p.ProviderName || f.State == "" || f.Verifier == "" {
		return "", fault.New(fault.InvalidRequest, "")
	}
	base := p.Authorize
	if base == "" {
		base = "https://idp.example/authorize"
	}
	q := url.Values{"state": {f.State}, "code_challenge": {f.Challenge()}, "code_challenge_method": {"S256"}}
	if f.Nonce != "" {
		q.Set("nonce", f.Nonce)
	}
	if f.Purpose != auth.PurposeSignIn {
		q.Set("prompt", "login")
	}
	return base + "?" + q.Encode(), nil
}

// Complete implements auth.ExternalProvider; a code works once.
func (p *Provider) Complete(_ context.Context, f auth.Flight, cb auth.Callback) (auth.Identity, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	if err := f.Accept(cb, now()); err != nil {
		return auth.Identity{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	id, ok := p.codes[cb.Code]
	if !ok || p.used[cb.Code] {
		return auth.Identity{}, fault.New(fault.AuthFailed, "")
	}
	p.used[cb.Code] = true
	return id, nil
}

// Links is an in-memory auth.IdentityLinks with the uniqueness rules of
// the contract. Provision creates the account through NewAccount, or
// refuses with fault.Forbidden when it is nil.
type Links struct {
	NewAccount func(id auth.Identity) (int64, error)
	// PerAccount limits the identities of one account (1 for LDAP per
	// provider and GitHub; 0 for no limit).
	PerAccount int

	mu     sync.Mutex
	next   int64
	linked []auth.LinkedIdentity
}

var _ auth.IdentityLinks = (*Links)(nil)

func (l *Links) find(id auth.Identity) int {
	return slices.IndexFunc(l.linked, func(li auth.LinkedIdentity) bool {
		return li.Provider == id.Provider && li.Issuer == id.Issuer && li.Subject == id.Subject
	})
}

// Account implements auth.IdentityLinks.
func (l *Links) Account(_ context.Context, id auth.Identity) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i := l.find(id); i >= 0 {
		return l.linked[i].UserID, nil
	}
	return 0, fault.New(fault.NotFound, "")
}

// Provision implements auth.IdentityLinks.
func (l *Links) Provision(ctx context.Context, id auth.Identity) (int64, error) {
	if l.NewAccount == nil {
		return 0, fault.New(fault.Forbidden, "")
	}
	userID, err := l.NewAccount(id)
	if err != nil {
		return 0, err
	}
	if _, err := l.link(userID, id, true); err != nil {
		return 0, err
	}
	return userID, nil
}

// LinkTx implements auth.IdentityLinks; the transaction is not used.
func (l *Links) LinkTx(_ context.Context, _ *store.Tx, userID int64, id auth.Identity) (auth.LinkedIdentity, error) {
	return l.link(userID, id, false)
}

func (l *Links) link(userID int64, id auth.Identity, provisioned bool) (auth.LinkedIdentity, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id.Subject == "" || l.find(id) >= 0 {
		return auth.LinkedIdentity{}, fault.New(fault.Conflict, "")
	}
	if l.PerAccount > 0 {
		n := 0
		for _, li := range l.linked {
			if li.UserID == userID && li.Provider == id.Provider && li.Issuer == id.Issuer {
				n++
			}
		}
		if n >= l.PerAccount {
			return auth.LinkedIdentity{}, fault.New(fault.Conflict, "")
		}
	}
	l.next++
	li := auth.LinkedIdentity{ID: l.next, UserID: userID, Provider: id.Provider, Issuer: id.Issuer,
		Subject: id.Subject, Username: id.Username, Provisioned: provisioned}
	l.linked = append(l.linked, li)
	return li, nil
}

// Unlink implements auth.IdentityLinks.
func (l *Links) Unlink(_ context.Context, userID, identityID int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	i := slices.IndexFunc(l.linked, func(li auth.LinkedIdentity) bool { return li.ID == identityID && li.UserID == userID })
	if i < 0 {
		return fault.New(fault.NotFound, "")
	}
	l.linked = slices.Delete(l.linked, i, i+1)
	return nil
}

// List implements auth.IdentityLinks.
func (l *Links) List(_ context.Context, userID int64) ([]auth.LinkedIdentity, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []auth.LinkedIdentity
	for _, li := range l.linked {
		if li.UserID == userID {
			out = append(out, li)
		}
	}
	return out, nil
}

// Revalidator is an auth.Revalidator that refuses the users in Refused and
// records every call.
type Revalidator struct {
	mu      sync.Mutex
	Refused map[int64]bool
	Calls   []int64
}

var _ auth.Revalidator = (*Revalidator)(nil)

// Revalidate implements auth.Revalidator.
func (r *Revalidator) Revalidate(_ context.Context, userID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Calls = append(r.Calls, userID)
	if r.Refused[userID] {
		return fault.New(fault.Forbidden, "")
	}
	return nil
}
