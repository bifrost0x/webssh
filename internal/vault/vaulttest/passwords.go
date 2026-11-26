package vaulttest

import (
	"bytes"
	"context"
	"sync"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/vault"
)

type assigned struct {
	userID      int64
	fingerprint string
	secret      []byte
}

// Passwords implements the provider method of saved passwords,
// (*vault.Service).Password, with the same checks: the resource must have
// an assignment of the user, and the target the caller connects to must
// have the fingerprint the assignment was confirmed for.
type Passwords struct {
	mu       sync.Mutex
	assigned map[string]assigned
	calls    int
}

// Assign stores secret for the resource of userID as confirmed for t.
func (p *Passwords) Assign(userID int64, resourceID string, t vault.Target, secret []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.assigned == nil {
		p.assigned = map[string]assigned{}
	}
	p.assigned[resourceID] = assigned{userID, vault.Fingerprint(t), bytes.Clone(secret)}
}

// Password returns a copy of the assigned secret. It fails with
// fault.CredentialMissing without an assignment of the user and with
// fault.CredentialTargetChanged when t differs from the confirmed target.
func (p *Passwords) Password(_ context.Context, userID int64, resourceID string, t vault.Target) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	a, ok := p.assigned[resourceID]
	switch {
	case !ok || a.userID != userID:
		return nil, fault.New(fault.CredentialMissing, "")
	case a.fingerprint != vault.Fingerprint(t):
		return nil, fault.New(fault.CredentialTargetChanged, "")
	}
	return bytes.Clone(a.secret), nil
}

// Calls returns the number of Password calls.
func (p *Passwords) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}
