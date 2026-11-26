package e2eseed

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Hook names of seed version 1.
const (
	HookAutomationSSHPeer      = "automation_ssh_peer"
	HookOutboundSSHGuard       = "outbound_ssh_guard"
	HookSocketOutputLoad       = "socket_output_load"
	HookSocketWorkspaceRestore = "socket_workspace_restore"
	HookSocketHerdrSessions    = "socket_herdr_sessions"
)

var knownHooks = []string{
	HookAutomationSSHPeer, HookOutboundSSHGuard, HookSocketOutputLoad,
	HookSocketWorkspaceRestore, HookSocketHerdrSessions,
}

// reservedEnvironment are set by the harness itself: the seed must not
// move the data directory out of the fresh scratch tree, and the test
// switches are read by the entry file only.
var reservedEnvironment = []string{"DATA_DIR", "BACKUP_TEMP_DIR", "TRANSFER_TEMP_DIR"}

const maxGuardMessage = 200

var envName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// Validate checks everything the applier relies on before any store is
// touched: unique refs, resolvable references to the same account, known
// hooks with their members, plain data file names and the environment.
func (s *Seed) Validate() error {
	if s.Version != Version {
		return errors.New("unsupported seed version")
	}
	if err := s.validateEnvironment(); err != nil {
		return err
	}
	accounts := map[string]bool{}
	usernames := map[string]bool{}
	for _, a := range s.Accounts {
		if a.Ref == "" || accounts[a.Ref] {
			return fmt.Errorf("account ref %q is empty or not unique", a.Ref)
		}
		if a.Username == "" || a.Password == "" || usernames[a.Username] {
			return fmt.Errorf("account %q: username and password are required, usernames unique", a.Ref)
		}
		accounts[a.Ref] = true
		usernames[a.Username] = true
	}
	account := func(section, ref string) error {
		if !accounts[ref] {
			return fmt.Errorf("%s: unknown account %q", section, ref)
		}
		return nil
	}
	for _, e := range s.ExternalIdentities {
		if err := account("external_identities", e.Account); err != nil {
			return err
		}
	}
	for _, e := range slices.Concat(s.Commands, s.CommandSets) {
		if err := account("commands", e.Account); err != nil {
			return err
		}
	}
	for _, f := range s.SecurityFeatures {
		if f.Feature == "" {
			return errors.New("security_features: feature is required")
		}
		if err := account("security_features", f.UpdatedBy); err != nil {
			return err
		}
	}
	for _, f := range s.MFAPlaceholders {
		if err := account("mfa_placeholders", f.Account); err != nil {
			return err
		}
		if err := f.validate(); err != nil {
			return err
		}
	}
	refs, err := s.validateConnections(account)
	if err != nil {
		return err
	}
	if err := s.validateProfiles(account, refs); err != nil {
		return err
	}
	return s.validateHooks(account)
}

func (s *Seed) validateEnvironment() error {
	for name, value := range s.Environment {
		if !envName.MatchString(name) || slices.Contains(reservedEnvironment, name) || strings.HasPrefix(name, "WEBSSH_E2E_") {
			return fmt.Errorf("environment: variable %q is not allowed", name)
		}
		if strings.ContainsRune(value, 0) {
			return fmt.Errorf("environment: %s contains NUL", name)
		}
		if rest, ok := strings.CutPrefix(value, dataDirPlaceholder); ok && !plainFileName(rest) {
			return fmt.Errorf("environment: %s must name a plain file in the data directory", name)
		}
	}
	for _, name := range s.UnsetEnvironment {
		if !envName.MatchString(name) || slices.Contains(reservedEnvironment, name) {
			return fmt.Errorf("unset_environment: variable %q is not allowed", name)
		}
		if _, set := s.Environment[name]; set {
			return fmt.Errorf("unset_environment: %s is also set", name)
		}
	}
	for name := range s.DataFiles {
		if !plainFileName(name) {
			return fmt.Errorf("data_files: %q must be a plain file name", name)
		}
	}
	return nil
}

func (f MFAPlaceholder) validate() error {
	switch f.Type {
	case "totp":
		if f.Label == "" || f.Name != "" || f.CredentialID != "" || f.PublicKey != "" || f.Transports != nil {
			return errors.New("mfa_placeholders: totp takes label, active and secret")
		}
	case "passkey":
		if f.Name == "" || f.CredentialID == "" || f.Label != "" || f.Secret != "" || f.Active != nil {
			return errors.New("mfa_placeholders: passkey takes name, credential_id, public_key and transports")
		}
	default:
		return fmt.Errorf("mfa_placeholders: unknown type %q", f.Type)
	}
	return nil
}

// refOwners maps the refs of keys, jump hosts and SOCKS proxies to their
// account.
type refOwners struct{ keys, jumpHosts, proxies map[string]string }

func (s *Seed) validateConnections(account func(string, string) error) (refOwners, error) {
	r := refOwners{keys: map[string]string{}, jumpHosts: map[string]string{}, proxies: map[string]string{}}
	add := func(section string, m map[string]string, ref, owner string) error {
		if err := account(section, owner); err != nil {
			return err
		}
		if _, dup := m[ref]; ref == "" || dup {
			return fmt.Errorf("%s: ref %q is empty or not unique", section, ref)
		}
		m[ref] = owner
		return nil
	}
	for _, k := range s.SSHKeys {
		if k.Generate != "ed25519" {
			return r, fmt.Errorf("ssh_keys %q: unsupported key type %q", k.Ref, k.Generate)
		}
		if err := add("ssh_keys", r.keys, k.Ref, k.Account); err != nil {
			return r, err
		}
	}
	for _, j := range s.JumpHosts {
		if err := add("jump_hosts", r.jumpHosts, j.Ref, j.Account); err != nil {
			return r, err
		}
		if err := endpoint("jump_hosts", j.Host, j.Port); err != nil {
			return r, err
		}
		if err := reference("jump_hosts", r.keys, j.Key, j.KeyID, j.Account); err != nil {
			return r, err
		}
	}
	for _, p := range s.SOCKSProxies {
		if err := add("socks_proxies", r.proxies, p.Ref, p.Account); err != nil {
			return r, err
		}
		if err := endpoint("socks_proxies", p.Host, p.Port); err != nil {
			return r, err
		}
	}
	return r, nil
}

func (s *Seed) validateProfiles(account func(string, string) error, r refOwners) error {
	ids := map[string]bool{}
	for _, p := range s.Profiles {
		if err := account("profiles", p.Account); err != nil {
			return err
		}
		key := p.Account + "\x00" + p.ID
		if p.ID == "" || p.Name == "" || ids[key] {
			return fmt.Errorf("profiles: id %q is empty or not unique, or the name is missing", p.ID)
		}
		ids[key] = true
		if err := endpoint("profiles", p.Host, p.Port); err != nil {
			return err
		}
		for _, ref := range []struct {
			m         map[string]string
			ref, id   string
			attribute string
		}{
			{r.keys, p.Key, p.KeyID, "key"},
			{r.jumpHosts, p.JumpHost, p.JumpHostID, "jump_host"},
			{r.proxies, p.SOCKSProxy, p.SOCKSProxyID, "socks_proxy"},
		} {
			if err := reference("profiles "+p.ID+" "+ref.attribute, ref.m, ref.ref, ref.id, p.Account); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Seed) validateHooks(account func(string, string) error) error {
	seen := map[string]bool{}
	for _, h := range s.TestHooks {
		if !slices.Contains(knownHooks, h.Name) {
			return fmt.Errorf("unknown test hook %q", h.Name)
		}
		if seen[h.Name] {
			return fmt.Errorf("test hook %q is listed twice", h.Name)
		}
		seen[h.Name] = true
		switch h.Name {
		case HookAutomationSSHPeer:
			if len(h.Accounts) == 0 || h.Error != "" {
				return fmt.Errorf("test hook %s takes accounts only", h.Name)
			}
			for _, ref := range h.Accounts {
				if err := account("test hook "+h.Name, ref); err != nil {
					return err
				}
			}
		case HookOutboundSSHGuard:
			if h.Accounts != nil || !safeMessage(h.Error) {
				return fmt.Errorf("test hook %s takes a short printable error text only", h.Name)
			}
		default:
			if h.Accounts != nil || h.Error != "" {
				return fmt.Errorf("test hook %s takes no members", h.Name)
			}
		}
	}
	return nil
}

// reference checks a symbolic ref (resolved to an id of the same account)
// against a literal id; at most one of them is set.
func reference(section string, owners map[string]string, ref, literal, account string) error {
	if ref == "" {
		return nil
	}
	if literal != "" {
		return fmt.Errorf("%s: set either the ref or the id, not both", section)
	}
	owner, ok := owners[ref]
	if !ok {
		return fmt.Errorf("%s: unknown ref %q", section, ref)
	}
	if owner != account {
		return fmt.Errorf("%s: ref %q belongs to another account", section, ref)
	}
	return nil
}

func endpoint(section, host string, port int) error {
	if host == "" || port < 1 || port > 65535 {
		return fmt.Errorf("%s: host %q or port %d is invalid", section, host, port)
	}
	return nil
}

func plainFileName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00:") && len(name) <= 255
}

// safeMessage reports whether text may be shown to a user as is.
func safeMessage(text string) bool {
	if text == "" || len(text) > maxGuardMessage {
		return false
	}
	for _, r := range text {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
