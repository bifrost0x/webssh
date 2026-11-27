package e2eseed

import (
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"fmt"
	"sync"
)

// fakeStores records what the applier writes, in order.
type fakeStores struct {
	mu       sync.Mutex
	calls    []string
	nextUser int64
	nextID   int
	users    map[int64]string
	admins   map[int64]bool
	mfa      map[int64]bool
	keys     map[string]ed25519.PrivateKey
	jumps    map[string]JumpHostRecord
	proxies  map[string]SOCKSProxyRecord
	profiles map[int64][]ProfileRecord
	commands map[int64][2][]jsontext.Value
	failOn   string
}

func newFakeStores() *fakeStores {
	return &fakeStores{
		users: map[int64]string{}, admins: map[int64]bool{}, mfa: map[int64]bool{},
		keys: map[string]ed25519.PrivateKey{}, jumps: map[string]JumpHostRecord{},
		proxies: map[string]SOCKSProxyRecord{}, profiles: map[int64][]ProfileRecord{},
		commands: map[int64][2][]jsontext.Value{},
	}
}

func (f *fakeStores) stores() Stores {
	return Stores{Accounts: f, AppSettings: f, UserSettings: f, FeatureGates: f, Factors: f, Keys: f, Hosts: f, Identities: f, Commands: f}
}

func (f *fakeStores) SeedCommands(_ context.Context, owner int64, cmds, sets []jsontext.Value) error {
	f.commands[owner] = [2][]jsontext.Value{cmds, sets}
	return f.record(fmt.Sprintf("commands %d %d %d", owner, len(cmds), len(sets)))
}

func (f *fakeStores) record(call string) error {
	f.calls = append(f.calls, call)
	if f.failOn != "" && call == f.failOn {
		return fmt.Errorf("fake store refused %s", call)
	}
	return nil
}

func (f *fakeStores) id(prefix string) string {
	f.nextID++
	return fmt.Sprintf("%s-%d", prefix, f.nextID)
}

func (f *fakeStores) CreateLocal(_ context.Context, username, _ string, admin bool) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u == username {
			return 0, fmt.Errorf("duplicate user %s", username)
		}
	}
	f.nextUser++
	f.users[f.nextUser] = username
	f.admins[f.nextUser] = admin
	return f.nextUser, f.record("account " + username)
}

func (f *fakeStores) MarkMFAEnabled(_ context.Context, userID int64) error {
	f.mfa[userID] = true
	return f.record(fmt.Sprintf("mfa %d", userID))
}

func (f *fakeStores) SetRegistrationEnabled(_ context.Context, enabled bool) error {
	return f.record(fmt.Sprintf("registration %t", enabled))
}

func (f *fakeStores) SetLoginUsernameLimits(_ context.Context, per, global int) error {
	return f.record(fmt.Sprintf("limits %d %d", per, global))
}

func (f *fakeStores) SetOnboarding(_ context.Context, userID int64, tour string, ack bool) error {
	return f.record(fmt.Sprintf("onboarding %d %s %t", userID, tour, ack))
}

func (f *fakeStores) SetFeature(_ context.Context, feature string, enabled bool, by int64) error {
	return f.record(fmt.Sprintf("feature %s %t %d", feature, enabled, by))
}

func (f *fakeStores) AddTOTPPlaceholder(_ context.Context, userID int64, label string, active bool) error {
	return f.record(fmt.Sprintf("totp %d %s %t", userID, label, active))
}

func (f *fakeStores) AddPasskeyPlaceholder(_ context.Context, userID int64, name, credentialID string, transports []string) error {
	return f.record(fmt.Sprintf("passkey %d %s %s %d", userID, name, credentialID, len(transports)))
}

func (f *fakeStores) AddKey(_ context.Context, owner int64, name string, key ed25519.PrivateKey) (string, error) {
	id := f.id("key")
	f.keys[id] = key
	return id, f.record(fmt.Sprintf("key %d %s", owner, name))
}

func (f *fakeStores) AddJumpHost(_ context.Context, owner int64, j JumpHostRecord) (string, error) {
	id := f.id("jump")
	f.jumps[id] = j
	return id, f.record(fmt.Sprintf("jump %d %s", owner, j.Name))
}

func (f *fakeStores) AddSOCKSProxy(_ context.Context, owner int64, p SOCKSProxyRecord) (string, error) {
	id := f.id("socks")
	f.proxies[id] = p
	return id, f.record(fmt.Sprintf("socks %d %s", owner, p.Name))
}

func (f *fakeStores) SaveProfiles(_ context.Context, owner int64, profiles []ProfileRecord) error {
	f.profiles[owner] = profiles
	return f.record(fmt.Sprintf("profiles %d %d", owner, len(profiles)))
}

func (f *fakeStores) LinkGitHub(_ context.Context, userID int64, id, login string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.record(fmt.Sprintf("github:%s:%s:%s", f.users[userID], id, login))
}

func (f *fakeStores) LinkOIDC(_ context.Context, userID int64, issuer, subject string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.record(fmt.Sprintf("oidc:%s:%s:%s", f.users[userID], issuer, subject))
}
