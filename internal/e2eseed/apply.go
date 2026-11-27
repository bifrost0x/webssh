package e2eseed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log/slog"
	"time"
)

// The interfaces below are what the applier needs from the Go stores. They
// are declared here, by the consumer, in terms of the seed's meaning and
// use only standard library types. The entry file cmd/webssh/e2e.go adapts
// the real stores to them, so no capability changes its API for the
// harness.

// Accounts creates local accounts.
type Accounts interface {
	// CreateLocal creates a local account with a password sign-in and
	// returns its user ID.
	CreateLocal(ctx context.Context, username, password string, admin bool) (userID int64, err error)
	// MarkMFAEnabled marks the account as enrolled in a second factor.
	MarkMFAEnabled(ctx context.Context, userID int64) error
}

// AppSettings holds the admin policies of the seed.
type AppSettings interface {
	SetRegistrationEnabled(ctx context.Context, enabled bool) error
	// SetLoginUsernameLimits raises the sign-in limits per username and
	// for all usernames together, so that many cases can sign in to the
	// same accounts.
	SetLoginUsernameLimits(ctx context.Context, perUsername, global int) error
	// SetAutomationEnabled stores the automation switch.
	SetAutomationEnabled(ctx context.Context, enabled bool) error
}

// HostKeys trusts host keys for an account (the automation peer).
type HostKeys interface {
	Record(ctx context.Context, owner int64, host string, port int, key ssh.PublicKey) error
}

// UserSettings stores per-account settings.
type UserSettings interface {
	// SetOnboarding records the state of the introduction tour.
	SetOnboarding(ctx context.Context, userID int64, tour string, v3Acknowledged bool) error
}

// FeatureGates switches the security features.
type FeatureGates interface {
	SetFeature(ctx context.Context, feature string, enabled bool, updatedBy int64) error
}

// Factors records second factors that only mark an account as enrolled.
// An implementation may store an unknown random secret or an unusable
// public key: the records must never authenticate anyone.
type Factors interface {
	AddTOTPPlaceholder(ctx context.Context, userID int64, label string, active bool) error
	AddPasskeyPlaceholder(ctx context.Context, userID int64, name, credentialID string, transports []string) error
}

// Keys stores SSH keys.
type Keys interface {
	// AddKey stores a key generated for this run and returns its id.
	AddKey(ctx context.Context, owner int64, name string, key ed25519.PrivateKey) (keyID string, err error)
}

// Hosts stores saved routes and hosts.
type Hosts interface {
	AddJumpHost(ctx context.Context, owner int64, j JumpHostRecord) (id string, err error)
	AddSOCKSProxy(ctx context.Context, owner int64, p SOCKSProxyRecord) (id string, err error)
	// SaveProfiles stores the account's profiles in the given order.
	SaveProfiles(ctx context.Context, owner int64, profiles []ProfileRecord) error
}

// JumpHostRecord is a jump host with its key reference resolved.
type JumpHostRecord struct {
	Name, Host     string
	Port           int
	Username, Auth string
	KeyID          string
}

// SOCKSProxyRecord is a SOCKS5 proxy.
type SOCKSProxyRecord struct {
	Name, Host     string
	Port           int
	Auth, Username string
	RemoteDNS      bool
}

// ProfileRecord is a profile with its references resolved to ids. The
// startup members are stored as given even where this build does not run
// them.
type ProfileRecord struct {
	ID, Name, Host                  string
	Port                            int
	Username, Auth, Group           string
	SortOrder                       *int
	Favorite                        bool
	KeyID, JumpHostID, SOCKSProxyID string
	StartupMode, StartupCommands    string
	CommandID, CommandSetID         string
	ParametersOverride              *string
}

// Stores are the stores the seed is applied to. Every field is required:
// a section this build applies must not be skipped because a store was
// not wired.
type Stores struct {
	Accounts     Accounts
	AppSettings  AppSettings
	UserSettings UserSettings
	FeatureGates FeatureGates
	Factors      Factors
	Keys         Keys
	Hosts        Hosts
	Identities   Identities
	Commands     Commands
	HostKeys     HostKeys
}

func (s Stores) complete() error {
	if s.Accounts == nil || s.AppSettings == nil || s.UserSettings == nil || s.FeatureGates == nil ||
		s.Factors == nil || s.Keys == nil || s.Hosts == nil || s.Identities == nil || s.Commands == nil ||
		s.HostKeys == nil {
		return errors.New("e2e seed: a store is not wired")
	}
	return nil
}

// Applied is the outcome of Apply.
type Applied struct {
	// Users maps account refs to user IDs.
	Users map[string]int64
	// Skipped names the parts of the seed this build does not apply.
	Skipped []string
	// Peer is the automation peer Apply started because the caller had
	// not (Run starts it before the backend); the caller closes it.
	Peer *AutomationPeer
}

// Apply writes the seed into the stores, in the order of run_app.py:
// admin settings, accounts, account settings, factors and feature gates,
// keys, jump hosts, SOCKS proxies, commands and command sets, profiles. Parts that belong to
// capabilities outside this build are logged and skipped (Skipped). The
// first error stops the run; the caller discards the data directory.
func Apply(ctx context.Context, s *Seed, st Stores, log *slog.Logger) (Applied, error) {
	if err := s.Validate(); err != nil {
		return Applied{}, err
	}
	if err := st.complete(); err != nil {
		return Applied{}, err
	}
	a := Applied{Users: map[string]int64{}, Skipped: s.skipped()}
	if s.peer == nil {
		p, err := s.StartAutomationPeer()
		if err != nil {
			return Applied{}, err
		}
		s.peer, a.Peer = p, p
	}
	for _, part := range a.Skipped {
		owner, _ := SkippedOwner(part)
		log.Info("e2e seed: skipped, not part of this build", "part", part, "package", owner)
	}
	steps := []func() error{
		func() error { return applyAdminSettings(ctx, s.AdminSettings, st.AppSettings) },
		func() error { return applyAccounts(ctx, s, st, a.Users) },
		func() error { return applyFactors(ctx, s, st, a.Users) },
		func() error { return applyIdentities(ctx, s, st, a.Users) },
		func() error { return applyConnections(ctx, s, st, a.Users) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return Applied{}, fmt.Errorf("e2e seed: %w", err)
		}
	}
	return a, nil
}

// skipped lists the non-empty parts of the seed outside this build.
func (s *Seed) skipped() []string {
	// Since the third wave of M2 this build applies every part of the
	// seed; a part added later without its applier is listed here.
	return nil
}

func applyAdminSettings(ctx context.Context, as AdminSettings, st AppSettings) error {
	if as.AutomationEnabled != nil {
		if err := st.SetAutomationEnabled(ctx, *as.AutomationEnabled); err != nil {
			return fmt.Errorf("automation setting: %w", err)
		}
	}
	if as.RegistrationEnabled != nil {
		if err := st.SetRegistrationEnabled(ctx, *as.RegistrationEnabled); err != nil {
			return fmt.Errorf("registration setting: %w", err)
		}
	}
	if as.LoginUsernameLimit == nil && as.LoginUsernameGlobalLimit == nil {
		return nil
	}
	if as.LoginUsernameLimit == nil || as.LoginUsernameGlobalLimit == nil ||
		*as.LoginUsernameLimit < 1 || *as.LoginUsernameGlobalLimit < *as.LoginUsernameLimit {
		return errors.New("login username limits: set both, global not below the per-username limit")
	}
	if err := st.SetLoginUsernameLimits(ctx, *as.LoginUsernameLimit, *as.LoginUsernameGlobalLimit); err != nil {
		return fmt.Errorf("login username limits: %w", err)
	}
	return nil
}

func applyAccounts(ctx context.Context, s *Seed, st Stores, users map[string]int64) error {
	for _, acc := range s.Accounts {
		id, err := st.Accounts.CreateLocal(ctx, acc.Username, acc.Password, acc.Admin)
		if err != nil {
			return fmt.Errorf("account %s: %w", acc.Ref, err)
		}
		users[acc.Ref] = id
	}
	// Accounts start with the tour already seen, so a spec that signs in
	// through the form does not depend on which spec ran first.
	if as := s.AccountSettings; as != nil {
		for _, acc := range s.Accounts {
			if err := st.UserSettings.SetOnboarding(ctx, users[acc.Ref], as.IntroTour, as.IntroTourV3Acknowledged); err != nil {
				return fmt.Errorf("account settings %s: %w", acc.Ref, err)
			}
		}
	}
	for _, acc := range s.Accounts {
		if acc.MFAEnabled {
			if err := st.Accounts.MarkMFAEnabled(ctx, users[acc.Ref]); err != nil {
				return fmt.Errorf("mfa flag %s: %w", acc.Ref, err)
			}
		}
	}
	return nil
}

func applyFactors(ctx context.Context, s *Seed, st Stores, users map[string]int64) error {
	for _, f := range s.SecurityFeatures {
		if err := st.FeatureGates.SetFeature(ctx, f.Feature, f.Enabled, users[f.UpdatedBy]); err != nil {
			return fmt.Errorf("security feature %s: %w", f.Feature, err)
		}
	}
	for _, f := range s.MFAPlaceholders {
		var err error
		switch f.Type {
		case "totp":
			err = st.Factors.AddTOTPPlaceholder(ctx, users[f.Account], f.Label, f.Active == nil || *f.Active)
		case "passkey":
			err = st.Factors.AddPasskeyPlaceholder(ctx, users[f.Account], f.Name, f.CredentialID, f.Transports)
		}
		if err != nil {
			return fmt.Errorf("%s placeholder for %s: %w", f.Type, f.Account, err)
		}
	}
	return nil
}

func applyConnections(ctx context.Context, s *Seed, st Stores, users map[string]int64) error {
	keys, jumps, proxies := map[string]string{}, map[string]string{}, map[string]string{}
	for _, k := range s.SSHKeys {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("ssh key %s: %w", k.Ref, err)
		}
		if keys[k.Ref], err = st.Keys.AddKey(ctx, users[k.Account], k.Name, priv); err != nil {
			return fmt.Errorf("ssh key %s: %w", k.Ref, err)
		}
	}
	var err error
	for _, j := range s.JumpHosts {
		rec := JumpHostRecord{Name: j.Name, Host: j.Host, Port: j.Port, Username: j.Username, Auth: j.AuthType, KeyID: resolve(keys, j.Key, j.KeyID)}
		if jumps[j.Ref], err = st.Hosts.AddJumpHost(ctx, users[j.Account], rec); err != nil {
			return fmt.Errorf("jump host %s: %w", j.Ref, err)
		}
	}
	for _, p := range s.SOCKSProxies {
		rec := SOCKSProxyRecord{Name: p.Name, Host: p.Host, Port: p.Port, Auth: p.AuthType, Username: p.Username, RemoteDNS: p.RemoteDNS}
		if proxies[p.Ref], err = st.Hosts.AddSOCKSProxy(ctx, users[p.Account], rec); err != nil {
			return fmt.Errorf("socks proxy %s: %w", p.Ref, err)
		}
	}
	if err := applyCommands(ctx, s, st.Commands, users, time.Now()); err != nil {
		return err
	}
	// Profiles are saved per account in first-appearance order.
	var order []string
	byAccount := map[string][]ProfileRecord{}
	for _, p := range s.Profiles {
		if _, seen := byAccount[p.Account]; !seen {
			order = append(order, p.Account)
		}
		mode := p.StartupMode
		if mode == "" {
			mode = "none"
		}
		byAccount[p.Account] = append(byAccount[p.Account], ProfileRecord{
			ID: p.ID, Name: p.Name, Host: p.Host, Port: p.Port, Username: p.Username, Auth: p.AuthType,
			Group: p.Group, SortOrder: p.SortOrder, Favorite: p.Favorite,
			KeyID:        resolve(keys, p.Key, p.KeyID),
			JumpHostID:   resolve(jumps, p.JumpHost, p.JumpHostID),
			SOCKSProxyID: resolve(proxies, p.SOCKSProxy, p.SOCKSProxyID),
			StartupMode:  mode, StartupCommands: p.StartupCommands,
			CommandID: p.CommandID, CommandSetID: p.CommandSetID, ParametersOverride: p.ParametersOverride,
		})
	}
	if p := s.peer; p != nil {
		for _, ref := range p.accounts {
			rec, err := p.seedAccount(ctx, st, users[ref])
			if err != nil {
				return fmt.Errorf("automation peer for %s: %w", ref, err)
			}
			if _, seen := byAccount[ref]; !seen {
				order = append(order, ref)
			}
			byAccount[ref] = append(byAccount[ref], rec)
		}
	}
	for _, ref := range order {
		if err := st.Hosts.SaveProfiles(ctx, users[ref], byAccount[ref]); err != nil {
			return fmt.Errorf("profiles of %s: %w", ref, err)
		}
	}
	return nil
}

// resolve returns the id assigned to ref, or the literal id. Validate
// guarantees that a non-empty ref is known.
func resolve(ids map[string]string, ref, literal string) string {
	if ref != "" {
		return ids[ref]
	}
	return literal
}
